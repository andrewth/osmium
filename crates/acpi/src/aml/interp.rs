//! The interpreter: state, loading definition blocks, and the entry points that run control methods.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_boot::acpi::Acpi;

use super::cursor::Cursor;
use super::error::AmlError;
use super::exec::Flow;
use super::host::{Host, PciAddress};
use super::name::NameSeg;
use super::namespace::{Data, Method, Namespace, Native, NodeId, Object, ObjectKind, ROOT};
use super::value::Value;
use crate::fadt::Fadt;

const HEADER: usize = 36;

/// Interpreter limits and the identity it presents to AML.
#[derive(Clone, Debug)]
pub struct Config {
    /// What `\_OS_` says. Firmware tests it to decide which quirks to apply, and much of it only
    /// exercises the full feature set for "Microsoft Windows NT", so that is the default (as Linux does).
    pub os_name: String,
    /// What `\_REV` says: the revision of the ACPI specification supported.
    pub revision: u64,
    /// How deeply terms may nest and methods may call each other before the interpreter gives up (each
    /// nested term, and each method call, is a level). The interpreter recurses once per level; a release
    /// build needs about 0.65 KiB of stack per level (the default of 96 fits in 64 KiB) and a debug build
    /// about eight times that. Lower this on a small stack. [`peak_depth`](Interpreter::peak_depth) says
    /// how deep real firmware goes.
    pub max_depth: usize,
    /// How many terms one call to [`evaluate`](Interpreter::evaluate) may execute, to stop a loop that
    /// never ends.
    pub max_steps: u64,
    /// How many microseconds of `Sleep` and `Stall` one call may request in total.
    pub max_sleep_us: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            os_name: String::from("Microsoft Windows NT"),
            revision: 2,
            max_depth: 96,
            max_steps: 20_000_000,
            max_sleep_us: 10_000_000,
        }
    }
}

/// The identity fields of a loaded definition block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableInfo {
    /// `DSDT`, `SSDT` or `PSDT`.
    pub signature: [u8; 4],
    /// The table's revision; below 2 means integers are 32 bits wide.
    pub revision: u8,
    /// The OEM id.
    pub oem_id: [u8; 6],
    /// The OEM table id.
    pub oem_table_id: [u8; 8],
    /// Length in bytes.
    pub length: u32,
}

/// What [`Interpreter::load_tables`] did.
#[derive(Debug, Default)]
pub struct LoadReport {
    /// The tables that loaded completely.
    pub loaded: Vec<TableInfo>,
    /// The tables that failed. What they declared before the error stays in the namespace.
    pub failed: Vec<(TableInfo, AmlError)>,
}

/// What [`Interpreter::initialize`] did.
#[derive(Debug, Default)]
pub struct InitReport {
    /// `_REG` methods run.
    pub reg_run: usize,
    /// `_INI` methods run.
    pub ini_run: usize,
    /// Devices found present or functioning.
    pub devices: usize,
    /// Methods that failed, by path. The rest of initialization carries on.
    pub errors: Vec<(String, AmlError)>,
}

/// A device in the namespace and its identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Where it is.
    pub node: NodeId,
    /// Its absolute path.
    pub path: String,
    /// `_HID`, as a string such as `PNP0A08`.
    pub hid: Option<String>,
    /// `_UID`.
    pub uid: Option<String>,
    /// `_ADR`.
    pub adr: Option<u64>,
    /// `_STA`, or 0xf (present, enabled, shown, functioning) if the device has none.
    pub status: u32,
}

/// One method invocation (or one evaluation of lazy data, or one definition block being loaded).
pub(crate) struct Frame {
    pub args: [Value; 7],
    pub locals: [Value; 8],
    pub scope: NodeId,
    pub code: Arc<[u8]>,
    pub int64: bool,
    /// Whether named objects created here go away when it ends (they do for a method, not for a table).
    pub track: bool,
    pub created: Vec<NodeId>,
}

/// An AML interpreter with its namespace and the [`Host`] it runs on.
pub struct Interpreter<H> {
    pub(crate) host: H,
    pub(crate) ns: Namespace,
    pub(crate) config: Config,
    pub(crate) frames: Vec<Frame>,
    pub(crate) depth: usize,
    peak_depth: usize,
    pub(crate) steps: u64,
    pub(crate) sleep_us: u64,
    pub(crate) events: BTreeMap<NodeId, u64>,
    pub(crate) pci_cache: BTreeMap<NodeId, PciAddress>,
    tables: Vec<TableInfo>,
    warnings: Vec<String>,
}

impl<H: Host> Interpreter<H> {
    /// An interpreter with the predefined namespace (`\_SB_`, `\_OS_`, `\_OSI` and the rest) and no tables.
    pub fn new(host: H, config: Config) -> Self {
        let mut ns = Namespace::new();
        for seg in [b"_GPE", b"_PR_", b"_SB_", b"_SI_", b"_TZ_"] {
            let _ = ns.insert(ROOT, NameSeg(*seg), Object::Scope);
        }
        let _ = ns.insert(ROOT, NameSeg(*b"_OS_"), Object::Data(Data::Ready(Value::String(config.os_name.clone()))));
        let _ = ns.insert(ROOT, NameSeg(*b"_REV"), Object::Data(Data::Ready(Value::Integer(config.revision))));
        let _ = ns.insert(ROOT, NameSeg(*b"_OSI"), Object::Native(Native::Osi));
        let _ = ns.insert(ROOT, NameSeg(*b"_GL_"), Object::Mutex);
        Self {
            host,
            ns,
            config,
            frames: Vec::new(),
            depth: 0,
            peak_depth: 0,
            steps: 0,
            sleep_us: 0,
            events: BTreeMap::new(),
            pci_cache: BTreeMap::new(),
            tables: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// The host.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// The host, mutably.
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// The namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.ns
    }

    /// The tables loaded so far, in load order.
    pub fn tables(&self) -> &[TableInfo] {
        &self.tables
    }

    /// The deepest nesting of terms and method calls reached so far, in the units [`Config::max_depth`]
    /// counts. Run the firmware's own methods and look at this to size that limit.
    pub fn peak_depth(&self) -> usize {
        self.peak_depth
    }

    /// Declarations skipped because the name was already taken, and similar recoverable oddities.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub(crate) fn warn(&mut self, msg: String) {
        if self.warnings.len() < 256 {
            self.warnings.push(msg);
        }
    }

    // ----- loading -----

    /// Parses `table` (a DSDT, SSDT or PSDT, header included) and runs its top-level terms, which declare
    /// its objects in the namespace. Method bodies and `Name` initializers are not run until used.
    ///
    /// A declaration whose name is already taken is skipped with a [warning](Self::warnings). Any other
    /// error stops the load, leaving what was declared so far.
    pub fn load_table(&mut self, table: &[u8]) -> Result<TableInfo, AmlError> {
        let info = parse_header(table)?;
        let len = info.length as usize;
        let code: Arc<[u8]> = Arc::from(table.get(..len).ok_or(AmlError::InvalidTable)?);
        self.tables.push(info.clone());
        self.enter(|s| {
            s.push_frame(ROOT, code.clone(), info.revision >= 2, false, Vec::new())?;
            let mut c = Cursor::new(&code, HEADER, len);
            let r = s.exec_list(&mut c);
            s.pop_frame();
            match r? {
                Flow::Next(_) => Ok(()),
                _ => Err(AmlError::BadControlFlow),
            }
        })?;
        Ok(info)
    }

    /// Loads the DSDT named by the FADT, then every SSDT and PSDT in the root table's order.
    ///
    /// Fails only if there is no FADT or no readable DSDT; a table that fails to load is listed in the
    /// report and the others still load.
    pub fn load_tables<'src, F>(&mut self, acpi: &Acpi<'src, F>) -> Result<LoadReport, AmlError>
    where
        F: Fn(u64, usize) -> Option<&'src [u8]>,
    {
        let fadt = acpi.find(b"FACP").and_then(Fadt::parse).ok_or(AmlError::InvalidTable)?;
        let dsdt = acpi.table_at_address(fadt.dsdt_address()).ok_or(AmlError::InvalidTable)?;
        let mut report = LoadReport::default();
        let mut load = |s: &mut Self, data: &[u8]| match s.load_table(data) {
            Ok(info) => report.loaded.push(info),
            Err(e) => match parse_header(data) {
                Ok(info) => report.failed.push((info, e)),
                Err(e2) => report.failed.push((placeholder_info(data), e2)),
            },
        };
        load(self, dsdt.data);
        for t in acpi.tables() {
            if matches!(&t.signature(), b"SSDT" | b"PSDT") {
                load(self, t.data);
            }
        }
        Ok(report)
    }

    /// Prepares the namespace for use, in the order ACPI describes: runs `_REG(space, 1)` for each operation
    /// region the [host serves](Host::serves_region), `\_SB_._INI`, and then `_STA` and `_INI` on every
    /// device, skipping the children of devices that are neither present nor functioning.
    pub fn initialize(&mut self) -> InitReport {
        let mut report = InitReport::default();
        self.run_reg(&mut report);
        if let Some(sb) = self.ns.find("\\_SB_._INI") {
            self.try_run(sb, &[], &mut report);
            report.ini_run += 1;
        }
        let mut skipped: BTreeSet<NodeId> = BTreeSet::new();
        for id in self.ns.descendants(ROOT) {
            if !matches!(self.ns.kind(id), Some(ObjectKind::Device | ObjectKind::Processor)) {
                continue;
            }
            let mut anc = self.ns.parent(id);
            let mut hidden = false;
            while let Some(a) = anc {
                if skipped.contains(&a) {
                    hidden = true;
                    break;
                }
                anc = self.ns.parent(a);
            }
            if hidden {
                continue;
            }
            let status = self.status(id, &mut report);
            if status & 0x9 == 0 {
                skipped.insert(id);
                continue;
            }
            report.devices += 1;
            if status & 1 != 0
                && let Some(ini) = self.ns.child(id, NameSeg(*b"_INI"))
            {
                self.try_run(ini, &[], &mut report);
                report.ini_run += 1;
            }
        }
        report
    }

    fn status(&mut self, dev: NodeId, report: &mut InitReport) -> u32 {
        let Some(sta) = self.ns.child(dev, NameSeg(*b"_STA")) else { return 0xf };
        match self.evaluate_node(sta, &[]) {
            Ok(Value::Integer(v)) => v as u32,
            Ok(_) => 0xf,
            Err(e) => {
                report.errors.push((self.ns.path(sta), e));
                0xf
            }
        }
    }

    fn try_run(&mut self, method: NodeId, args: &[Value], report: &mut InitReport) {
        if let Err(e) = self.evaluate_node(method, args) {
            report.errors.push((self.ns.path(method), e));
        }
    }

    fn run_reg(&mut self, report: &mut InitReport) {
        let mut done: BTreeSet<(NodeId, u8)> = BTreeSet::new();
        for id in self.ns.descendants(ROOT) {
            let Some(Object::Region(r)) = self.ns.object(id) else { continue };
            let space = r.space;
            let Some(parent) = self.ns.parent(id) else { continue };
            let Some(reg) = self.ns.child(parent, NameSeg(*b"_REG")) else { continue };
            if !self.host.serves_region(space) || !done.insert((parent, space)) {
                continue;
            }
            self.try_run(reg, &[Value::Integer(u64::from(space)), Value::Integer(1)], report);
            report.reg_run += 1;
        }
    }

    // ----- evaluation -----

    /// Evaluates the object at `path` (absolute, such as `\_SB_.PCI0._CRS`, or relative to the root): runs
    /// it if it is a method, reads it otherwise.
    pub fn evaluate(&mut self, path: &str, args: &[Value]) -> Result<Value, AmlError> {
        let id = self.ns.find(path).ok_or(AmlError::NotFound)?;
        self.evaluate_node(id, args)
    }

    /// Like [`evaluate`](Self::evaluate) for an object already found.
    pub fn evaluate_node(&mut self, id: NodeId, args: &[Value]) -> Result<Value, AmlError> {
        if args.len() > 7 {
            return Err(AmlError::WrongArgCount);
        }
        self.enter(|s| {
            let id = s.ns.resolve_alias(id);
            if matches!(s.ns.kind(id), Some(ObjectKind::Method)) {
                return s.call(id, args.to_vec());
            }
            if !args.is_empty() {
                return Err(AmlError::WrongArgCount);
            }
            s.push_frame(ROOT, Arc::from([]), true, true, Vec::new())?;
            let r = s.read_node(id);
            s.pop_frame();
            r
        })
    }

    /// Evaluates `path` to an integer, converting if needed.
    pub fn evaluate_integer(&mut self, path: &str, args: &[Value]) -> Result<u64, AmlError> {
        let v = self.evaluate(path, args)?;
        self.enter(|s| {
            s.push_frame(ROOT, Arc::from([]), true, true, Vec::new())?;
            let r = s.integer_from(v);
            s.pop_frame();
            r
        })
    }

    /// Whether the object has a child named `name` (for example `_PRT` under a bridge).
    pub fn has_child(&self, id: NodeId, name: &str) -> bool {
        super::namespace::parse_path(name)
            .ok()
            .and_then(|(_, segs)| segs.first().copied())
            .is_some_and(|seg| self.ns.child(id, seg).is_some())
    }

    /// Every `Device` with its identity. Evaluates `_HID`, `_UID`, `_ADR` and `_STA` of each.
    pub fn devices(&mut self) -> Vec<DeviceInfo> {
        let mut out = Vec::new();
        for id in self.ns.descendants(ROOT) {
            if self.ns.kind(id) != Some(ObjectKind::Device) {
                continue;
            }
            let hid = self.child_id_string(id, *b"_HID");
            let uid = self.child_id_string(id, *b"_UID");
            let adr = self.child_value(id, *b"_ADR").and_then(|v| v.as_integer());
            let status = match self.child_value(id, *b"_STA") {
                Some(Value::Integer(v)) => v as u32,
                _ => 0xf,
            };
            out.push(DeviceInfo { node: id, path: self.ns.path(id), hid, uid, adr, status });
        }
        out
    }

    /// Devices whose `_HID` or any `_CID` is `hid`.
    pub fn find_devices(&mut self, hid: &str) -> Vec<NodeId> {
        let mut out = Vec::new();
        for id in self.ns.descendants(ROOT) {
            if self.ns.kind(id) == Some(ObjectKind::Device) && self.device_matches(id, hid) {
                out.push(id);
            }
        }
        out
    }

    pub(crate) fn device_matches(&mut self, id: NodeId, hid: &str) -> bool {
        if self.child_id_string(id, *b"_HID").is_some_and(|h| h == hid) {
            return true;
        }
        match self.child_value(id, *b"_CID") {
            Some(Value::Package(items)) => items.iter().any(|v| id_string(v, true).is_some_and(|s| s == hid)),
            Some(v) => id_string(&v, true).is_some_and(|s| s == hid),
            None => false,
        }
    }

    /// Evaluates the child `name` of `id`, if it exists and succeeds.
    pub(crate) fn child_value(&mut self, id: NodeId, name: [u8; 4]) -> Option<Value> {
        let child = self.ns.child(id, NameSeg(name))?;
        self.evaluate_node(child, &[]).ok()
    }

    fn child_id_string(&mut self, id: NodeId, name: [u8; 4]) -> Option<String> {
        id_string(&self.child_value(id, name)?, name != *b"_UID")
    }

    // ----- running -----

    /// Runs `f` as an outermost call: budgets start fresh and any frames it leaves behind are popped.
    pub(crate) fn enter<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, AmlError>) -> Result<T, AmlError> {
        let base = self.frames.len();
        let depth = self.depth;
        if base == 0 {
            self.steps = 0;
            self.sleep_us = 0;
        }
        let r = f(self);
        self.unwind(base);
        self.depth = depth;
        r
    }

    pub(crate) fn push_frame(
        &mut self,
        scope: NodeId,
        code: Arc<[u8]>,
        int64: bool,
        track: bool,
        args: Vec<Value>,
    ) -> Result<(), AmlError> {
        self.descend()?;
        let mut a: [Value; 7] = core::array::from_fn(|_| Value::Uninit);
        for (slot, v) in a.iter_mut().zip(args) {
            *slot = v;
        }
        self.frames.push(Frame {
            args: a,
            locals: core::array::from_fn(|_| Value::Uninit),
            scope,
            code,
            int64,
            track,
            created: Vec::new(),
        });
        Ok(())
    }

    pub(crate) fn pop_frame(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        if let Some(f) = self.frames.pop() {
            for id in f.created {
                self.ns.remove(id);
            }
        }
    }

    fn unwind(&mut self, to: usize) {
        while self.frames.len() > to {
            self.pop_frame();
        }
    }

    /// Counts one more level of nesting.
    pub(crate) fn descend(&mut self) -> Result<(), AmlError> {
        self.depth += 1;
        self.peak_depth = self.peak_depth.max(self.depth);
        if self.depth > self.config.max_depth { Err(AmlError::TooDeep) } else { Ok(()) }
    }

    /// Runs a method or a native method with `args`.
    pub(crate) fn call(&mut self, id: NodeId, args: Vec<Value>) -> Result<Value, AmlError> {
        match self.ns.object(id) {
            Some(Object::Method(m)) => {
                let m: Method = m.clone();
                if args.len() != usize::from(m.args) {
                    return Err(AmlError::WrongArgCount);
                }
                self.push_frame(id, m.code.clone(), m.int64, true, args)?;
                let mut c = Cursor::new(&m.code, m.start, m.end);
                let r = self.exec_list(&mut c);
                self.pop_frame();
                match r? {
                    Flow::Return(v) => Ok(v),
                    Flow::Next(_) => Ok(Value::Uninit),
                    _ => Err(AmlError::BadControlFlow),
                }
            }
            Some(Object::Native(Native::Osi)) => {
                let [arg] = args.as_slice() else { return Err(AmlError::WrongArgCount) };
                let Value::String(name) = arg else { return Err(AmlError::TypeMismatch) };
                let yes = self.host.supports_interface(name);
                Ok(Value::Integer(if yes { u64::MAX } else { 0 }))
            }
            _ => Err(AmlError::TypeMismatch),
        }
    }
}

/// Reads a definition block's header.
pub(crate) fn parse_header(t: &[u8]) -> Result<TableInfo, AmlError> {
    if t.len() < HEADER {
        return Err(AmlError::InvalidTable);
    }
    let signature: [u8; 4] = t.first_chunk().copied().ok_or(AmlError::InvalidTable)?;
    if !matches!(&signature, b"DSDT" | b"SSDT" | b"PSDT") {
        return Err(AmlError::InvalidTable);
    }
    let length = u32::from_le_bytes(t.get(4..8).and_then(|b| b.first_chunk().copied()).ok_or(AmlError::InvalidTable)?);
    let body = t.get(..length as usize).ok_or(AmlError::InvalidTable)?;
    if (length as usize) < HEADER || body.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return Err(AmlError::InvalidTable);
    }
    Ok(TableInfo {
        signature,
        revision: *t.get(8).ok_or(AmlError::InvalidTable)?,
        oem_id: t.get(10..16).and_then(|b| b.first_chunk().copied()).ok_or(AmlError::InvalidTable)?,
        oem_table_id: t.get(16..24).and_then(|b| b.first_chunk().copied()).ok_or(AmlError::InvalidTable)?,
        length,
    })
}

fn placeholder_info(t: &[u8]) -> TableInfo {
    TableInfo {
        signature: t.first_chunk().copied().unwrap_or([0; 4]),
        revision: 0,
        oem_id: [0; 6],
        oem_table_id: [0; 8],
        length: t.len() as u32,
    }
}

/// A `_HID`, `_CID` or `_UID` value as text: strings as they are, integers as decimal, or for a hardware id
/// (`eisa`) decoded as a compressed EISA id (`0x030AD041` is `PNP0A03`) when they look like one.
pub(crate) fn id_string(v: &Value, eisa: bool) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => Some(eisa.then(|| eisa_id(*i)).flatten().unwrap_or_else(|| alloc::format!("{i}"))),
        _ => None,
    }
}

/// Decodes a compressed EISA id.
pub(crate) fn eisa_id(v: u64) -> Option<String> {
    let v = u32::try_from(v).ok()?.swap_bytes();
    let letter = |shift: u32| {
        let c = ((v >> shift) & 0x1f) as u8 + 0x40;
        c.is_ascii_uppercase().then_some(char::from(c))
    };
    let mut s = String::with_capacity(7);
    s.push(letter(26)?);
    s.push(letter(21)?);
    s.push(letter(16)?);
    for shift in [12, 8, 4, 0] {
        s.push(char::from_digit((v >> shift) & 0xf, 16)?.to_ascii_uppercase());
    }
    Some(s)
}
