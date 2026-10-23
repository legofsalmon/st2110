//! The NMOS Control model a Device exposes through IS-12 v1.0.1: the MS-05-02 v1.0
//! framework's classes and datatypes, and the monitoring feature set's status monitors
//! that BCP-008-01 v1.0 (Receivers) and BCP-008-02 v1.0 (Senders) ask for.
//!
//! A Device advertises its IS-12 endpoint, a WebSocket, in its IS-04 `controls` as
//! [`CONTROL_TYPE`]. Over it a controller sends `Command` messages, each calling a
//! method of one object by its `oid`, and `Subscription` messages naming the objects
//! whose `PropertyChanged` events it wants as `Notification` messages.
//!
//! Every object derives from `NcObject`. The root block (`oid` 1, role `root`) holds the
//! `DeviceManager`, the `ClassManager`, and here one `NcReceiverMonitor` or
//! `NcSenderMonitor` whose `touchpoints` name the IS-04 Receiver or Sender it watches.
//!
//! This module holds the model as data: the ids of the elements a controller and a
//! Device use, and the class and datatype descriptors the `ClassManager` serves.
//! [`client`] talks to a Device's endpoint.
//!
//! ```
//! use st2110_nmos::ncp::{self, class, property};
//!
//! let monitor = ncp::class(class::RECEIVER_MONITOR).unwrap();
//! assert_eq!(monitor.name, "NcReceiverMonitor");
//! let status = monitor.property(property::OVERALL_STATUS).unwrap();
//! assert_eq!((status.name, status.type_name), ("overallStatus", Some("NcOverallStatus")));
//! assert_eq!(ncp::enum_name("NcOverallStatus", 3), Some("Unhealthy"));
//! ```

#[cfg(feature = "client")]
pub mod client;

use serde_json::{Value, json};

/// The control type a Device lists in its IS-04 `controls` for its IS-12 endpoint.
pub const CONTROL_TYPE: &str = "urn:x-nmos:control:ncp/v1.0";

/// Every version of the control type starts with this.
pub const CONTROL_PREFIX: &str = "urn:x-nmos:control:ncp";

/// The version of MS-05-02 this model follows, as `NcDeviceManager.ncVersion` gives it.
pub const NC_VERSION: &str = "v1.0.0";

/// IS-12 message types (Protocol messaging).
pub mod message {
    /// A controller's commands.
    pub const COMMAND: u64 = 0;
    /// The Device's answers to them.
    pub const COMMAND_RESPONSE: u64 = 1;
    /// Events the controller subscribed to.
    pub const NOTIFICATION: u64 = 2;
    /// The objects a controller wants events from.
    pub const SUBSCRIPTION: u64 = 3;
    /// The objects it now has events from.
    pub const SUBSCRIPTION_RESPONSE: u64 = 4;
    /// A message the Device could not take.
    pub const ERROR: u64 = 5;
}

/// A property, method or event of a class: the level of the class that defines it, and
/// its index there (MS-05-02 element ids, written `1p1`, `1m1`, `1e1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ElementId {
    /// The inheritance level of the class that defines it.
    pub level: u16,
    /// Its ordinal within that class.
    pub index: u16,
}

impl ElementId {
    /// The element `index` of level `level`.
    pub const fn new(level: u16, index: u16) -> Self {
        Self { level, index }
    }

    /// As IS-12 sends it: `{"level": 1, "index": 1}`.
    pub fn json(self) -> Value {
        json!({"level": self.level, "index": self.index})
    }

    /// Reads one sent as IS-12 sends it.
    pub fn from_json(value: &Value) -> Option<Self> {
        let part = |name: &str| value.get(name)?.as_u64().and_then(|n| u16::try_from(n).ok());
        Some(Self { level: part("level")?, index: part("index")? })
    }
}

/// The ids of the properties a controller reads.
pub mod property {
    use super::ElementId;

    /// `NcObject.classId`.
    pub const CLASS_ID: ElementId = ElementId::new(1, 1);
    /// `NcObject.oid`.
    pub const OID: ElementId = ElementId::new(1, 2);
    /// `NcObject.constantOid`.
    pub const CONSTANT_OID: ElementId = ElementId::new(1, 3);
    /// `NcObject.owner`.
    pub const OWNER: ElementId = ElementId::new(1, 4);
    /// `NcObject.role`.
    pub const ROLE: ElementId = ElementId::new(1, 5);
    /// `NcObject.userLabel`.
    pub const USER_LABEL: ElementId = ElementId::new(1, 6);
    /// `NcObject.touchpoints`.
    pub const TOUCHPOINTS: ElementId = ElementId::new(1, 7);
    /// `NcObject.runtimePropertyConstraints`.
    pub const RUNTIME_PROPERTY_CONSTRAINTS: ElementId = ElementId::new(1, 8);
    /// `NcBlock.enabled` and `NcWorker.enabled`.
    pub const ENABLED: ElementId = ElementId::new(2, 1);
    /// `NcBlock.members`.
    pub const MEMBERS: ElementId = ElementId::new(2, 2);
    /// `NcStatusMonitor.overallStatus`.
    pub const OVERALL_STATUS: ElementId = ElementId::new(3, 1);
    /// `NcStatusMonitor.overallStatusMessage`.
    pub const OVERALL_STATUS_MESSAGE: ElementId = ElementId::new(3, 2);
    /// `NcStatusMonitor.statusReportingDelay`, in seconds.
    pub const STATUS_REPORTING_DELAY: ElementId = ElementId::new(3, 3);
    /// `linkStatus` of a Receiver or Sender monitor.
    pub const LINK_STATUS: ElementId = ElementId::new(4, 1);
    /// `linkStatusMessage`.
    pub const LINK_STATUS_MESSAGE: ElementId = ElementId::new(4, 2);
    /// `linkStatusTransitionCounter`.
    pub const LINK_STATUS_TRANSITION_COUNTER: ElementId = ElementId::new(4, 3);
    /// A Receiver monitor's `connectionStatus`, a Sender monitor's `transmissionStatus`.
    pub const CONNECTION_STATUS: ElementId = ElementId::new(4, 4);
    /// Its message.
    pub const CONNECTION_STATUS_MESSAGE: ElementId = ElementId::new(4, 5);
    /// Its transition counter.
    pub const CONNECTION_STATUS_TRANSITION_COUNTER: ElementId = ElementId::new(4, 6);
    /// `externalSynchronizationStatus`.
    pub const SYNCHRONIZATION_STATUS: ElementId = ElementId::new(4, 7);
    /// Its message.
    pub const SYNCHRONIZATION_STATUS_MESSAGE: ElementId = ElementId::new(4, 8);
    /// Its transition counter.
    pub const SYNCHRONIZATION_STATUS_TRANSITION_COUNTER: ElementId = ElementId::new(4, 9);
    /// `synchronizationSourceId`.
    pub const SYNCHRONIZATION_SOURCE_ID: ElementId = ElementId::new(4, 10);
    /// A Receiver monitor's `streamStatus`, a Sender monitor's `essenceStatus`.
    pub const STREAM_STATUS: ElementId = ElementId::new(4, 11);
    /// Its message.
    pub const STREAM_STATUS_MESSAGE: ElementId = ElementId::new(4, 12);
    /// Its transition counter.
    pub const STREAM_STATUS_TRANSITION_COUNTER: ElementId = ElementId::new(4, 13);
    /// `autoResetCountersAndMessages`.
    pub const AUTO_RESET: ElementId = ElementId::new(4, 14);
}

/// The ids of the methods a controller calls.
pub mod method {
    use super::ElementId;

    /// `NcObject.Get(id)`.
    pub const GET: ElementId = ElementId::new(1, 1);
    /// `NcObject.Set(id, value)`.
    pub const SET: ElementId = ElementId::new(1, 2);
    /// `NcObject.GetSequenceItem(id, index)`.
    pub const GET_SEQUENCE_ITEM: ElementId = ElementId::new(1, 3);
    /// `NcObject.SetSequenceItem(id, index, value)`.
    pub const SET_SEQUENCE_ITEM: ElementId = ElementId::new(1, 4);
    /// `NcObject.AddSequenceItem(id, value)`.
    pub const ADD_SEQUENCE_ITEM: ElementId = ElementId::new(1, 5);
    /// `NcObject.RemoveSequenceItem(id, index)`.
    pub const REMOVE_SEQUENCE_ITEM: ElementId = ElementId::new(1, 6);
    /// `NcObject.GetSequenceLength(id)`.
    pub const GET_SEQUENCE_LENGTH: ElementId = ElementId::new(1, 7);
    /// `NcBlock.GetMemberDescriptors(recurse)`.
    pub const GET_MEMBER_DESCRIPTORS: ElementId = ElementId::new(2, 1);
    /// `NcBlock.FindMembersByPath(path)`.
    pub const FIND_MEMBERS_BY_PATH: ElementId = ElementId::new(2, 2);
    /// `NcBlock.FindMembersByRole(role, caseSensitive, matchWholeString, recurse)`.
    pub const FIND_MEMBERS_BY_ROLE: ElementId = ElementId::new(2, 3);
    /// `NcBlock.FindMembersByClassId(classId, includeDerived, recurse)`.
    pub const FIND_MEMBERS_BY_CLASS_ID: ElementId = ElementId::new(2, 4);
    /// `NcClassManager.GetControlClass(classId, includeInherited)`.
    pub const GET_CONTROL_CLASS: ElementId = ElementId::new(3, 1);
    /// `NcClassManager.GetDatatype(name, includeInherited)`.
    pub const GET_DATATYPE: ElementId = ElementId::new(3, 2);
    /// `NcReceiverMonitor.GetLostPacketCounters()`.
    pub const GET_LOST_PACKET_COUNTERS: ElementId = ElementId::new(4, 1);
    /// `NcReceiverMonitor.GetLatePacketCounters()`.
    pub const GET_LATE_PACKET_COUNTERS: ElementId = ElementId::new(4, 2);
    /// `NcReceiverMonitor.ResetCountersAndMessages()`.
    pub const RESET_RECEIVER_COUNTERS: ElementId = ElementId::new(4, 3);
    /// `NcSenderMonitor.GetTransmissionErrorCounters()`.
    pub const GET_TRANSMISSION_ERROR_COUNTERS: ElementId = ElementId::new(4, 1);
    /// `NcSenderMonitor.ResetCountersAndMessages()`.
    pub const RESET_SENDER_COUNTERS: ElementId = ElementId::new(4, 2);
}

/// `NcObject.PropertyChanged`, the one event.
pub const PROPERTY_CHANGED: ElementId = ElementId::new(1, 1);

/// The class ids of the classes this model holds.
pub mod class {
    /// `NcObject`.
    pub const OBJECT: &[i64] = &[1];
    /// `NcBlock`.
    pub const BLOCK: &[i64] = &[1, 1];
    /// `NcWorker`.
    pub const WORKER: &[i64] = &[1, 2];
    /// `NcStatusMonitor`, which every status monitor derives from.
    pub const STATUS_MONITOR: &[i64] = &[1, 2, 2];
    /// `NcReceiverMonitor` (BCP-008-01).
    pub const RECEIVER_MONITOR: &[i64] = &[1, 2, 2, 1];
    /// `NcSenderMonitor` (BCP-008-02).
    pub const SENDER_MONITOR: &[i64] = &[1, 2, 2, 2];
    /// `NcManager`.
    pub const MANAGER: &[i64] = &[1, 3];
    /// `NcDeviceManager`.
    pub const DEVICE_MANAGER: &[i64] = &[1, 3, 1];
    /// `NcClassManager`.
    pub const CLASS_MANAGER: &[i64] = &[1, 3, 2];
}

/// Whether the class `id` is `base` or derives from it, such as a vendor's variant of
/// `NcReceiverMonitor`, whose id continues `base`'s (MS-05-02 NcClassId).
pub fn derives(id: &[i64], base: &[i64]) -> bool {
    id.starts_with(base)
}

/// A class id as JSON gives it, when it is one.
pub fn class_id(value: &Value) -> Option<Vec<i64>> {
    value.as_array()?.iter().map(Value::as_i64).collect()
}

/// A property of a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Property {
    /// Its element id.
    pub id: ElementId,
    /// Its name, such as `overallStatus`.
    pub name: &'static str,
    /// Its datatype; `None` for any.
    pub type_name: Option<&'static str>,
    /// Whether `Set` refuses it.
    pub read_only: bool,
    /// Whether it may be null.
    pub nullable: bool,
    /// Whether it is a sequence of its type.
    pub sequence: bool,
    /// What it is.
    pub description: &'static str,
}

impl Property {
    /// Its `NcPropertyDescriptor`.
    pub fn descriptor(&self) -> Value {
        json!({
            "description": self.description, "id": self.id.json(), "name": self.name, "typeName": self.type_name,
            "isReadOnly": self.read_only, "isNullable": self.nullable, "isSequence": self.sequence,
            "isDeprecated": false, "constraints": null,
        })
    }
}

/// A property as the tables write it: level, index, name, type (`any` for any), flags
/// (`r` read only, `?` nullable, `*` sequence) and description.
type P = (u16, u16, &'static str, &'static str, &'static str, &'static str);

/// A method as the tables write it: level, index, name, result type, parameters as
/// `name:Type` (`?` after a nullable type, `*` after a sequence) and description.
type M = (u16, u16, &'static str, &'static str, &'static [&'static str], &'static str);

/// A field or parameter written `name:Type`, `Type?` for nullable, `Type*` for a
/// sequence and `any` for any type: its name, type, nullable and sequence.
fn field(text: &'static str) -> (&'static str, Option<&'static str>, bool, bool) {
    let (name, kind) = text.split_once(':').unwrap_or((text, "any?"));
    let nullable = kind.contains('?');
    let sequence = kind.contains('*');
    let kind = kind.trim_end_matches(['?', '*']);
    (name, (kind != "any").then_some(kind), nullable || kind == "any", sequence)
}

fn field_descriptor(text: &'static str) -> Value {
    let (name, type_name, nullable, sequence) = field(text);
    json!({"description": null, "name": name, "typeName": type_name, "isNullable": nullable,
           "isSequence": sequence, "constraints": null})
}

/// A control class.
#[derive(Debug)]
pub struct Class {
    /// Its class id.
    pub id: &'static [i64],
    /// Its name, such as `NcReceiverMonitor`.
    pub name: &'static str,
    /// The role every instance has, for a manager.
    pub fixed_role: Option<&'static str>,
    /// What it is.
    pub description: &'static str,
    properties: &'static [P],
    methods: &'static [M],
}

impl Class {
    /// The class it derives from.
    pub fn parent(&self) -> Option<&'static Class> {
        class(self.id.get(..self.id.len().checked_sub(1)?)?)
    }

    /// Itself, then each class it derives from.
    fn lineage(&self) -> Vec<&Class> {
        let mut classes = vec![self];
        let mut next = self.parent();
        while let Some(class) = next {
            classes.push(class);
            next = class.parent();
        }
        classes
    }

    /// The properties it defines, without those it inherits.
    pub fn own_properties(&self) -> impl Iterator<Item = Property> + '_ {
        self.properties.iter().map(|&(level, index, name, kind, flags, description)| Property {
            id: ElementId::new(level, index),
            name,
            type_name: (kind != "any").then_some(kind),
            read_only: flags.contains('r'),
            nullable: flags.contains('?') || kind == "any",
            sequence: flags.contains('*'),
            description,
        })
    }

    /// Every property, its own and those it inherits.
    pub fn properties(&self) -> Vec<Property> {
        self.lineage().into_iter().flat_map(Class::own_properties).collect()
    }

    /// The property with this id, its own or inherited.
    pub fn property(&self, id: ElementId) -> Option<Property> {
        self.properties().into_iter().find(|p| p.id == id)
    }

    /// The property with this name, its own or inherited.
    pub fn property_named(&self, name: &str) -> Option<Property> {
        self.properties().into_iter().find(|p| p.name == name)
    }

    /// The ids of its methods, its own and those it inherits, in the order of its
    /// class descriptor.
    pub fn methods(&self) -> Vec<ElementId> {
        self.lineage().iter().flat_map(|class| class.methods.iter().map(|m| ElementId::new(m.0, m.1))).collect()
    }

    /// Whether it has, or inherits, the method `id`.
    pub fn has_method(&self, id: ElementId) -> bool {
        self.lineage().iter().any(|class| class.methods.iter().any(|m| ElementId::new(m.0, m.1) == id))
    }

    /// Its `NcClassDescriptor`, with what it inherits or without.
    pub fn descriptor(&self, include_inherited: bool) -> Value {
        let classes = if include_inherited { self.lineage() } else { vec![self] };
        let properties: Vec<Value> = classes.iter().flat_map(|c| c.own_properties()).map(|p| p.descriptor()).collect();
        let methods: Vec<Value> = classes
            .iter()
            .flat_map(|c| c.methods.iter())
            .map(|&(level, index, name, result, parameters, description)| {
                json!({
                    "description": description, "id": ElementId::new(level, index).json(), "name": name,
                    "resultDatatype": result,
                    "parameters": parameters.iter().map(|p| field_descriptor(p)).collect::<Vec<_>>(),
                    "isDeprecated": false,
                })
            })
            .collect();
        let events: Vec<Value> = classes
            .iter()
            .filter(|c| c.id == class::OBJECT)
            .map(|_| {
                json!({"description": "Property changed event", "id": PROPERTY_CHANGED.json(), "name": "PropertyChanged",
                       "eventDatatype": "NcPropertyChangedEventData", "isDeprecated": false})
            })
            .collect();
        json!({
            "description": self.description, "classId": self.id, "name": self.name, "fixedRole": self.fixed_role,
            "properties": properties, "methods": methods, "events": events,
        })
    }
}

/// The classes of the model, from the MS-05-02 framework and the monitoring feature set.
pub static CLASSES: &[Class] = &[
    Class {
        id: class::OBJECT,
        name: "NcObject",
        fixed_role: None,
        description: "NcObject class descriptor",
        properties: &[
            (
                1,
                1,
                "classId",
                "NcClassId",
                "r",
                "Static value. All instances of the same class will have the same identity value",
            ),
            (1, 2, "oid", "NcOid", "r", "Object identifier"),
            (1, 3, "constantOid", "NcBoolean", "r", "TRUE iff OID is hardwired into device"),
            (1, 4, "owner", "NcOid", "r?", "OID of containing block. Can only ever be null for the root block"),
            (1, 5, "role", "NcString", "r", "Role of object in the containing block"),
            (1, 6, "userLabel", "NcString", "?", "Scribble strip"),
            (1, 7, "touchpoints", "NcTouchpoint", "r?*", "Touchpoints to other contexts"),
            (1, 8, "runtimePropertyConstraints", "NcPropertyConstraints", "r?*", "Runtime property constraints"),
        ],
        methods: &[
            (1, 1, "Get", "NcMethodResultPropertyValue", &["id:NcPropertyId"], "Get property value"),
            (1, 2, "Set", "NcMethodResult", &["id:NcPropertyId", "value:any"], "Set property value"),
            (
                1,
                3,
                "GetSequenceItem",
                "NcMethodResultPropertyValue",
                &["id:NcPropertyId", "index:NcId"],
                "Get sequence item",
            ),
            (
                1,
                4,
                "SetSequenceItem",
                "NcMethodResult",
                &["id:NcPropertyId", "index:NcId", "value:any"],
                "Set sequence item value",
            ),
            (1, 5, "AddSequenceItem", "NcMethodResultId", &["id:NcPropertyId", "value:any"], "Add item to sequence"),
            (1, 6, "RemoveSequenceItem", "NcMethodResult", &["id:NcPropertyId", "index:NcId"], "Delete sequence item"),
            (1, 7, "GetSequenceLength", "NcMethodResultLength", &["id:NcPropertyId"], "Get sequence length"),
        ],
    },
    Class {
        id: class::BLOCK,
        name: "NcBlock",
        fixed_role: None,
        description: "NcBlock class descriptor",
        properties: &[
            (2, 1, "enabled", "NcBoolean", "r", "TRUE if block is functional"),
            (2, 2, "members", "NcBlockMemberDescriptor", "r*", "Descriptors of this block's members"),
        ],
        methods: &[
            (
                2,
                1,
                "GetMemberDescriptors",
                "NcMethodResultBlockMemberDescriptors",
                &["recurse:NcBoolean"],
                "Gets descriptors of members of the block",
            ),
            (
                2,
                2,
                "FindMembersByPath",
                "NcMethodResultBlockMemberDescriptors",
                &["path:NcRolePath"],
                "Finds member(s) by path",
            ),
            (
                2,
                3,
                "FindMembersByRole",
                "NcMethodResultBlockMemberDescriptors",
                &["role:NcString", "caseSensitive:NcBoolean", "matchWholeString:NcBoolean", "recurse:NcBoolean"],
                "Finds members with given role name or fragment",
            ),
            (
                2,
                4,
                "FindMembersByClassId",
                "NcMethodResultBlockMemberDescriptors",
                &["classId:NcClassId", "includeDerived:NcBoolean", "recurse:NcBoolean"],
                "Finds members with given class id",
            ),
        ],
    },
    Class {
        id: class::WORKER,
        name: "NcWorker",
        fixed_role: None,
        description: "NcWorker class descriptor",
        properties: &[(2, 1, "enabled", "NcBoolean", "", "TRUE iff worker is enabled")],
        methods: &[],
    },
    Class {
        id: class::STATUS_MONITOR,
        name: "NcStatusMonitor",
        fixed_role: None,
        description: "NcStatusMonitor class descriptor",
        properties: &[
            (3, 1, "overallStatus", "NcOverallStatus", "r", "Overall status property"),
            (3, 2, "overallStatusMessage", "NcString", "r?", "Overall status message property"),
            (
                3,
                3,
                "statusReportingDelay",
                "NcUint32",
                "",
                "Status reporting delay property (in seconds, default is 3s and 0 means no delay)",
            ),
        ],
        methods: &[],
    },
    Class {
        id: class::RECEIVER_MONITOR,
        name: "NcReceiverMonitor",
        fixed_role: None,
        description: "NcReceiverMonitor class descriptor",
        properties: &[
            (4, 1, "linkStatus", "NcLinkStatus", "r", "Link status property"),
            (4, 2, "linkStatusMessage", "NcString", "r?", "Link status message property"),
            (4, 3, "linkStatusTransitionCounter", "NcUint64", "r", "Link status transition counter property"),
            (4, 4, "connectionStatus", "NcConnectionStatus", "r", "Connection status property"),
            (4, 5, "connectionStatusMessage", "NcString", "r?", "Connection status message property"),
            (
                4,
                6,
                "connectionStatusTransitionCounter",
                "NcUint64",
                "r",
                "Connection status transition counter property",
            ),
            (
                4,
                7,
                "externalSynchronizationStatus",
                "NcSynchronizationStatus",
                "r",
                "External synchronization status property",
            ),
            (
                4,
                8,
                "externalSynchronizationStatusMessage",
                "NcString",
                "r?",
                "External synchronization status message property",
            ),
            (
                4,
                9,
                "externalSynchronizationStatusTransitionCounter",
                "NcUint64",
                "r",
                "External synchronization status transition counter property",
            ),
            (4, 10, "synchronizationSourceId", "NcString", "r?", "Synchronization source id property"),
            (4, 11, "streamStatus", "NcStreamStatus", "r", "Stream status property"),
            (4, 12, "streamStatusMessage", "NcString", "r?", "Stream status message property"),
            (4, 13, "streamStatusTransitionCounter", "NcUint64", "r", "Stream status transition counter property"),
            (
                4,
                14,
                "autoResetCountersAndMessages",
                "NcBoolean",
                "",
                "Automatic reset counters and status messages property (default: true)",
            ),
        ],
        methods: &[
            (4, 1, "GetLostPacketCounters", "NcMethodResultCounters", &[], "Gets the lost packet counters"),
            (4, 2, "GetLatePacketCounters", "NcMethodResultCounters", &[], "Gets the late packet counters"),
            (4, 3, "ResetCountersAndMessages", "NcMethodResult", &[], "Resets ALL counters and status messages"),
        ],
    },
    Class {
        id: class::SENDER_MONITOR,
        name: "NcSenderMonitor",
        fixed_role: None,
        description: "NcSenderMonitor class descriptor",
        properties: &[
            (4, 1, "linkStatus", "NcLinkStatus", "r", "Link status property"),
            (4, 2, "linkStatusMessage", "NcString", "r?", "Link status message property"),
            (4, 3, "linkStatusTransitionCounter", "NcUint64", "r", "Link status transition counter property"),
            (4, 4, "transmissionStatus", "NcTransmissionStatus", "r", "Transmission status property"),
            (4, 5, "transmissionStatusMessage", "NcString", "r?", "Transmission status message property"),
            (
                4,
                6,
                "transmissionStatusTransitionCounter",
                "NcUint64",
                "r",
                "Transmission status transition counter property",
            ),
            (
                4,
                7,
                "externalSynchronizationStatus",
                "NcSynchronizationStatus",
                "r",
                "External synchronization status property",
            ),
            (
                4,
                8,
                "externalSynchronizationStatusMessage",
                "NcString",
                "r?",
                "External synchronization status message property",
            ),
            (
                4,
                9,
                "externalSynchronizationStatusTransitionCounter",
                "NcUint64",
                "r",
                "External synchronization status transition counter property",
            ),
            (4, 10, "synchronizationSourceId", "NcString", "r?", "Synchronization source id property"),
            (4, 11, "essenceStatus", "NcEssenceStatus", "r", "Essence status property"),
            (4, 12, "essenceStatusMessage", "NcString", "r?", "Essence status message property"),
            (4, 13, "essenceStatusTransitionCounter", "NcUint64", "r", "Essence status transition counter property"),
            (
                4,
                14,
                "autoResetCountersAndMessages",
                "NcBoolean",
                "",
                "Automatic reset counters and status messages property (default: true)",
            ),
        ],
        methods: &[
            (
                4,
                1,
                "GetTransmissionErrorCounters",
                "NcMethodResultCounters",
                &[],
                "Gets the transmission error counters",
            ),
            (4, 2, "ResetCountersAndMessages", "NcMethodResult", &[], "Resets ALL counters and status messages"),
        ],
    },
    Class {
        id: class::MANAGER,
        name: "NcManager",
        fixed_role: None,
        description: "NcManager class descriptor",
        properties: &[],
        methods: &[],
    },
    Class {
        id: class::DEVICE_MANAGER,
        name: "NcDeviceManager",
        fixed_role: Some("DeviceManager"),
        description: "NcDeviceManager class descriptor",
        properties: &[
            (3, 1, "ncVersion", "NcVersionCode", "r", "Version of MS-05-02 that this device uses"),
            (3, 2, "manufacturer", "NcManufacturer", "r", "Manufacturer descriptor"),
            (3, 3, "product", "NcProduct", "r", "Product descriptor"),
            (3, 4, "serialNumber", "NcString", "r", "Serial number"),
            (3, 5, "userInventoryCode", "NcString", "?", "Asset tracking identifier (user specified)"),
            (
                3,
                6,
                "deviceName",
                "NcString",
                "?",
                "Name of this device in the application. Instance name, not product name.",
            ),
            (3, 7, "deviceRole", "NcString", "?", "Role of this device in the application."),
            (3, 8, "operationalState", "NcDeviceOperationalState", "r", "Device operational state"),
            (3, 9, "resetCause", "NcResetCause", "r", "Reason for most recent reset"),
            (3, 10, "message", "NcString", "r?", "Arbitrary message from dev to controller"),
        ],
        methods: &[],
    },
    Class {
        id: class::CLASS_MANAGER,
        name: "NcClassManager",
        fixed_role: Some("ClassManager"),
        description: "NcClassManager class descriptor",
        properties: &[
            (
                3,
                1,
                "controlClasses",
                "NcClassDescriptor",
                "r*",
                "Descriptions of all control classes in the device (descriptors do not contain inherited elements)",
            ),
            (
                3,
                2,
                "datatypes",
                "NcDatatypeDescriptor",
                "r*",
                "Descriptions of all data types in the device (descriptors do not contain inherited elements)",
            ),
        ],
        methods: &[
            (
                3,
                1,
                "GetControlClass",
                "NcMethodResultClassDescriptor",
                &["classId:NcClassId", "includeInherited:NcBoolean"],
                "Get a single class descriptor",
            ),
            (
                3,
                2,
                "GetDatatype",
                "NcMethodResultDatatypeDescriptor",
                &["name:NcName", "includeInherited:NcBoolean"],
                "Get a single datatype descriptor",
            ),
        ],
    },
];

/// The class with this id.
pub fn class(id: &[i64]) -> Option<&'static Class> {
    CLASSES.iter().find(|c| c.id == id)
}

/// The nearest class of this model that `id` is or derives from: for a vendor's
/// variant, the standard class it extends.
pub fn known_class(id: &[i64]) -> Option<&'static Class> {
    (1..=id.len()).rev().find_map(|n| class(&id[..n]))
}

/// A datatype of the model.
#[derive(Debug)]
enum Datatype {
    Primitive(&'static str),
    /// Name, parent type, whether a sequence of it, description.
    Typedef(&'static str, &'static str, bool, &'static str),
    /// Name, items and values, description.
    Enum(&'static str, &'static [(&'static str, u16)], &'static str),
    /// Name, parent struct, fields as `name:Type`, description.
    Struct(&'static str, Option<&'static str>, &'static [&'static str], &'static str),
}

const STATUSES: &[(&str, u16)] = &[("Inactive", 0), ("Healthy", 1), ("PartiallyHealthy", 2), ("Unhealthy", 3)];

static DATATYPES: &[Datatype] = &[
    Datatype::Primitive("NcBoolean"),
    Datatype::Primitive("NcInt16"),
    Datatype::Primitive("NcInt32"),
    Datatype::Primitive("NcInt64"),
    Datatype::Primitive("NcUint16"),
    Datatype::Primitive("NcUint32"),
    Datatype::Primitive("NcUint64"),
    Datatype::Primitive("NcFloat32"),
    Datatype::Primitive("NcFloat64"),
    Datatype::Primitive("NcString"),
    Datatype::Typedef("NcClassId", "NcInt32", true, "Sequence of class ID fields."),
    Datatype::Typedef("NcId", "NcUint32", false, "Identity handler"),
    Datatype::Typedef(
        "NcName",
        "NcString",
        false,
        "Programmatically significant name, alphanumerics + underscore, no spaces",
    ),
    Datatype::Typedef("NcOid", "NcUint32", false, "Object id"),
    Datatype::Typedef("NcOrganizationId", "NcInt32", false, "Unique 24-bit organization id"),
    Datatype::Typedef("NcRegex", "NcString", false, "Regex pattern"),
    Datatype::Typedef("NcRolePath", "NcString", true, "Role path"),
    Datatype::Typedef("NcTimeInterval", "NcInt64", false, "Time interval described in nanoseconds"),
    Datatype::Typedef("NcUri", "NcString", false, "Uniform resource identifier"),
    Datatype::Typedef("NcUuid", "NcString", false, "UUID"),
    Datatype::Typedef("NcVersionCode", "NcString", false, "Version code in semantic versioning format"),
    Datatype::Enum("NcDatatypeType", &[("Primitive", 0), ("Typedef", 1), ("Struct", 2), ("Enum", 3)], "Datatype type"),
    Datatype::Enum(
        "NcDeviceGenericState",
        &[
            ("Unknown", 0),
            ("NormalOperation", 1),
            ("Initializing", 2),
            ("Updating", 3),
            ("LicensingError", 4),
            ("InternalError", 5),
        ],
        "Device generic operational state",
    ),
    Datatype::Enum(
        "NcMethodStatus",
        &[
            ("Ok", 200),
            ("PropertyDeprecated", 298),
            ("MethodDeprecated", 299),
            ("BadCommandFormat", 400),
            ("Unauthorized", 401),
            ("BadOid", 404),
            ("Readonly", 405),
            ("InvalidRequest", 406),
            ("Conflict", 409),
            ("BufferOverflow", 413),
            ("IndexOutOfBounds", 414),
            ("ParameterError", 417),
            ("Locked", 423),
            ("DeviceError", 500),
            ("MethodNotImplemented", 501),
            ("PropertyNotImplemented", 502),
            ("NotReady", 503),
            ("Timeout", 504),
        ],
        "Method invokation status",
    ),
    Datatype::Enum(
        "NcPropertyChangeType",
        &[("ValueChanged", 0), ("SequenceItemAdded", 1), ("SequenceItemChanged", 2), ("SequenceItemRemoved", 3)],
        "Type of property change",
    ),
    Datatype::Enum(
        "NcResetCause",
        &[
            ("Unknown", 0),
            ("PowerOn", 1),
            ("InternalError", 2),
            ("Upgrade", 3),
            ("ControllerRequest", 4),
            ("ManualReset", 5),
        ],
        "Reset cause enum",
    ),
    Datatype::Enum("NcOverallStatus", STATUSES, "Overall status enum data type"),
    Datatype::Enum("NcLinkStatus", &[("AllUp", 1), ("SomeDown", 2), ("AllDown", 3)], "Link status enum data type"),
    Datatype::Enum("NcConnectionStatus", STATUSES, "Connection status enum data type"),
    Datatype::Enum("NcTransmissionStatus", STATUSES, "Transmission status enum data type"),
    Datatype::Enum(
        "NcSynchronizationStatus",
        &[("NotUsed", 0), ("Healthy", 1), ("PartiallyHealthy", 2), ("Unhealthy", 3)],
        "Synchronization status enum data type",
    ),
    Datatype::Enum("NcStreamStatus", STATUSES, "Stream status enum data type"),
    Datatype::Enum("NcEssenceStatus", STATUSES, "Essence status enum data type"),
    Datatype::Struct(
        "NcElementId",
        None,
        &["level:NcUint16", "index:NcUint16"],
        "Class element id which contains the level and index",
    ),
    Datatype::Struct("NcEventId", Some("NcElementId"), &[], "Event id which contains the level and index"),
    Datatype::Struct("NcMethodId", Some("NcElementId"), &[], "Method id which contains the level and index"),
    Datatype::Struct("NcPropertyId", Some("NcElementId"), &[], "Property id which contains the level and index"),
    Datatype::Struct("NcDescriptor", None, &["description:NcString?"], "Base descriptor"),
    Datatype::Struct(
        "NcBlockMemberDescriptor",
        Some("NcDescriptor"),
        &[
            "role:NcString",
            "oid:NcOid",
            "constantOid:NcBoolean",
            "classId:NcClassId",
            "userLabel:NcString?",
            "owner:NcOid",
        ],
        "Descriptor which is specific to a block member",
    ),
    Datatype::Struct(
        "NcClassDescriptor",
        Some("NcDescriptor"),
        &[
            "classId:NcClassId",
            "name:NcName",
            "fixedRole:NcString?",
            "properties:NcPropertyDescriptor*",
            "methods:NcMethodDescriptor*",
            "events:NcEventDescriptor*",
        ],
        "Descriptor of a class",
    ),
    Datatype::Struct(
        "NcDatatypeDescriptor",
        Some("NcDescriptor"),
        &["name:NcName", "type:NcDatatypeType", "constraints:NcParameterConstraints?"],
        "Base datatype descriptor",
    ),
    Datatype::Struct(
        "NcDatatypeDescriptorEnum",
        Some("NcDatatypeDescriptor"),
        &["items:NcEnumItemDescriptor*"],
        "Enum datatype descriptor",
    ),
    Datatype::Struct(
        "NcDatatypeDescriptorPrimitive",
        Some("NcDatatypeDescriptor"),
        &[],
        "Primitive datatype descriptor",
    ),
    Datatype::Struct(
        "NcDatatypeDescriptorStruct",
        Some("NcDatatypeDescriptor"),
        &["fields:NcFieldDescriptor*", "parentType:NcName?"],
        "Struct datatype descriptor",
    ),
    Datatype::Struct(
        "NcDatatypeDescriptorTypeDef",
        Some("NcDatatypeDescriptor"),
        &["parentType:NcName", "isSequence:NcBoolean"],
        "Type def datatype descriptor",
    ),
    Datatype::Struct(
        "NcEnumItemDescriptor",
        Some("NcDescriptor"),
        &["name:NcName", "value:NcUint16"],
        "Descriptor of an enum item",
    ),
    Datatype::Struct(
        "NcEventDescriptor",
        Some("NcDescriptor"),
        &["id:NcEventId", "name:NcName", "eventDatatype:NcName", "isDeprecated:NcBoolean"],
        "Descriptor of a class event",
    ),
    Datatype::Struct(
        "NcFieldDescriptor",
        Some("NcDescriptor"),
        &[
            "name:NcName",
            "typeName:NcName?",
            "isNullable:NcBoolean",
            "isSequence:NcBoolean",
            "constraints:NcParameterConstraints?",
        ],
        "Descriptor of a field of a struct",
    ),
    Datatype::Struct(
        "NcMethodDescriptor",
        Some("NcDescriptor"),
        &[
            "id:NcMethodId",
            "name:NcName",
            "resultDatatype:NcName",
            "parameters:NcParameterDescriptor*",
            "isDeprecated:NcBoolean",
        ],
        "Descriptor of a class method",
    ),
    Datatype::Struct(
        "NcParameterDescriptor",
        Some("NcDescriptor"),
        &[
            "name:NcName",
            "typeName:NcName?",
            "isNullable:NcBoolean",
            "isSequence:NcBoolean",
            "constraints:NcParameterConstraints?",
        ],
        "Descriptor of a method parameter",
    ),
    Datatype::Struct(
        "NcPropertyDescriptor",
        Some("NcDescriptor"),
        &[
            "id:NcPropertyId",
            "name:NcName",
            "typeName:NcName?",
            "isReadOnly:NcBoolean",
            "isNullable:NcBoolean",
            "isSequence:NcBoolean",
            "isDeprecated:NcBoolean",
            "constraints:NcParameterConstraints?",
        ],
        "Descriptor of a class property",
    ),
    Datatype::Struct(
        "NcDeviceOperationalState",
        None,
        &["generic:NcDeviceGenericState", "deviceSpecificDetails:NcString?"],
        "Device operational state",
    ),
    Datatype::Struct(
        "NcManufacturer",
        None,
        &["name:NcString", "organizationId:NcOrganizationId?", "website:NcUri?"],
        "Manufacturer descriptor",
    ),
    Datatype::Struct(
        "NcProduct",
        None,
        &[
            "name:NcString",
            "key:NcString",
            "revisionLevel:NcString",
            "brandName:NcString?",
            "uuid:NcUuid?",
            "description:NcString?",
        ],
        "Product descriptor",
    ),
    Datatype::Struct("NcMethodResult", None, &["status:NcMethodStatus"], "Base result of the invoked method"),
    Datatype::Struct(
        "NcMethodResultBlockMemberDescriptors",
        Some("NcMethodResult"),
        &["value:NcBlockMemberDescriptor*"],
        "Method result containing block member descriptors as the value",
    ),
    Datatype::Struct(
        "NcMethodResultClassDescriptor",
        Some("NcMethodResult"),
        &["value:NcClassDescriptor"],
        "Method result containing a class descriptor as the value",
    ),
    Datatype::Struct(
        "NcMethodResultDatatypeDescriptor",
        Some("NcMethodResult"),
        &["value:NcDatatypeDescriptor"],
        "Method result containing a datatype descriptor as the value",
    ),
    Datatype::Struct(
        "NcMethodResultError",
        Some("NcMethodResult"),
        &["errorMessage:NcString"],
        "Error result - to be used when the method call encounters an error",
    ),
    Datatype::Struct("NcMethodResultId", Some("NcMethodResult"), &["value:NcId"], "Id method result"),
    Datatype::Struct("NcMethodResultLength", Some("NcMethodResult"), &["value:NcUint32?"], "Length method result"),
    Datatype::Struct(
        "NcMethodResultPropertyValue",
        Some("NcMethodResult"),
        &["value:any"],
        "Result when invoking the getter method associated with a property",
    ),
    Datatype::Struct("NcMethodResultCounters", Some("NcMethodResult"), &["value:NcCounter*"], "Counters method result"),
    Datatype::Struct(
        "NcCounter",
        None,
        &["name:NcString", "value:NcUint64", "description:NcString?"],
        "Counter data type",
    ),
    Datatype::Struct("NcParameterConstraints", None, &["defaultValue:any"], "Abstract parameter constraints class"),
    Datatype::Struct(
        "NcParameterConstraintsNumber",
        Some("NcParameterConstraints"),
        &["maximum:any", "minimum:any", "step:any"],
        "Number parameter constraints class",
    ),
    Datatype::Struct(
        "NcParameterConstraintsString",
        Some("NcParameterConstraints"),
        &["maxCharacters:NcUint32?", "pattern:NcRegex?"],
        "String parameter constraints class",
    ),
    Datatype::Struct(
        "NcPropertyConstraints",
        None,
        &["propertyId:NcPropertyId", "defaultValue:any"],
        "Property constraints class",
    ),
    Datatype::Struct(
        "NcPropertyConstraintsNumber",
        Some("NcPropertyConstraints"),
        &["maximum:any", "minimum:any", "step:any"],
        "Number property constraints class",
    ),
    Datatype::Struct(
        "NcPropertyConstraintsString",
        Some("NcPropertyConstraints"),
        &["maxCharacters:NcUint32?", "pattern:NcRegex?"],
        "String property constraints class",
    ),
    Datatype::Struct(
        "NcPropertyChangedEventData",
        None,
        &["propertyId:NcPropertyId", "changeType:NcPropertyChangeType", "value:any", "sequenceItemIndex:NcId?"],
        "Payload of property-changed event",
    ),
    Datatype::Struct("NcTouchpoint", None, &["contextNamespace:NcString"], "Base touchpoint class"),
    Datatype::Struct(
        "NcTouchpointNmos",
        Some("NcTouchpoint"),
        &["resource:NcTouchpointResourceNmos"],
        "Touchpoint class for NMOS resources",
    ),
    Datatype::Struct(
        "NcTouchpointNmosChannelMapping",
        Some("NcTouchpoint"),
        &["resource:NcTouchpointResourceNmosChannelMapping"],
        "Touchpoint class for NMOS IS-08 resources",
    ),
    Datatype::Struct("NcTouchpointResource", None, &["resourceType:NcString"], "Touchpoint resource class"),
    Datatype::Struct(
        "NcTouchpointResourceNmos",
        Some("NcTouchpointResource"),
        &["id:NcUuid"],
        "Touchpoint resource class for NMOS resources",
    ),
    Datatype::Struct(
        "NcTouchpointResourceNmosChannelMapping",
        Some("NcTouchpointResourceNmos"),
        &["ioId:NcString"],
        "Touchpoint resource class for NMOS resources",
    ),
];

impl Datatype {
    fn name(&self) -> &'static str {
        match self {
            Self::Primitive(name) | Self::Typedef(name, ..) | Self::Enum(name, ..) | Self::Struct(name, ..) => name,
        }
    }

    fn descriptor(&self, include_inherited: bool) -> Value {
        match self {
            Self::Primitive(name) => {
                json!({"description": "Primitive datatype", "name": name, "type": 0, "constraints": null})
            }
            Self::Typedef(name, parent, sequence, description) => json!({
                "description": description, "name": name, "type": 1, "constraints": null,
                "parentType": parent, "isSequence": sequence,
            }),
            Self::Enum(name, items, description) => json!({
                "description": description, "name": name, "type": 3, "constraints": null,
                "items": items.iter().map(|(item, value)| json!({"description": null, "name": item, "value": value}))
                    .collect::<Vec<_>>(),
            }),
            Self::Struct(name, parent, fields, description) => {
                let mut all: Vec<Value> = Vec::new();
                if include_inherited {
                    let mut chain = Vec::new();
                    let mut next = *parent;
                    while let Some(Self::Struct(_, up, fields, _)) = next.and_then(find_datatype) {
                        chain.push(*fields);
                        next = *up;
                    }
                    for fields in chain.into_iter().rev() {
                        all.extend(fields.iter().map(|f| field_descriptor(f)));
                    }
                }
                all.extend(fields.iter().map(|f| field_descriptor(f)));
                json!({
                    "description": description, "name": name, "type": 2, "constraints": null,
                    "fields": all, "parentType": parent,
                })
            }
        }
    }
}

fn find_datatype(name: &str) -> Option<&'static Datatype> {
    DATATYPES.iter().find(|d| d.name() == name)
}

/// The `NcDatatypeDescriptor` of the datatype `name`, with the fields it inherits or
/// without.
pub fn datatype(name: &str, include_inherited: bool) -> Option<Value> {
    find_datatype(name).map(|d| d.descriptor(include_inherited))
}

/// Every datatype's descriptor, without inherited fields, as `NcClassManager.datatypes`
/// gives them.
pub fn datatypes() -> Vec<Value> {
    DATATYPES.iter().map(|d| d.descriptor(false)).collect()
}

/// Every class's descriptor, without inherited elements, as
/// `NcClassManager.controlClasses` gives them.
pub fn control_classes() -> Vec<Value> {
    CLASSES.iter().map(|c| c.descriptor(false)).collect()
}

/// The name of an enum's value, such as `Unhealthy` for 3 of `NcOverallStatus`.
pub fn enum_name(datatype: &str, value: u64) -> Option<&'static str> {
    match find_datatype(datatype)? {
        Datatype::Enum(_, items, _) => items.iter().find(|(_, v)| u64::from(*v) == value).map(|(name, _)| *name),
        _ => None,
    }
}

/// A status as BCP-008 ranks it, for the worst of several: neutral (`Inactive`,
/// `NotUsed`) 0, healthy 1, partially healthy 2, unhealthy 3. Link statuses (`AllUp`
/// 1 to `AllDown` 3) rank by their value too.
pub fn severity(value: u64) -> u64 {
    value.min(3)
}

/// An IS-12 `Command` message of one command.
pub fn command(handle: u64, oid: u64, method: ElementId, arguments: Value) -> Value {
    json!({"messageType": message::COMMAND, "commands": [
        {"handle": handle, "oid": oid, "methodId": method.json(), "arguments": arguments},
    ]})
}

/// An IS-12 `Subscription` message.
pub fn subscription(oids: &[u64]) -> Value {
    json!({"messageType": message::SUBSCRIPTION, "subscriptions": oids})
}

/// The touchpoint that names an NMOS resource, as BCP-008 has a monitor name the
/// Receiver or Sender it watches: `kind` is `receiver` or `sender`.
pub fn touchpoint(kind: &str, id: &str) -> Value {
    json!({"contextNamespace": "x-nmos", "resource": {"resourceType": kind, "id": id}})
}

/// The NMOS resources a list of touchpoints names: `(resourceType, id)`.
pub fn touchpoint_resources(touchpoints: &Value) -> Vec<(&str, &str)> {
    touchpoints
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t.get("contextNamespace").and_then(Value::as_str) == Some("x-nmos"))
        .filter_map(|t| {
            let resource = t.get("resource")?;
            Some((resource.get("resourceType")?.as_str()?, resource.get("id")?.as_str()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_inherit_and_describe_themselves() {
        let monitor = class(class::SENDER_MONITOR).unwrap();
        assert_eq!(monitor.parent().unwrap().name, "NcStatusMonitor");
        let names: Vec<&str> = monitor.properties().iter().map(|p| p.name).collect();
        assert!(names.starts_with(&["linkStatus"]) && names.contains(&"statusReportingDelay"), "{names:?}");
        assert!(names.contains(&"enabled") && names.ends_with(&["runtimePropertyConstraints"]), "{names:?}");
        assert!(monitor.has_method(method::GET) && monitor.has_method(method::RESET_SENDER_COUNTERS));
        assert!(!class(class::DEVICE_MANAGER).unwrap().has_method(method::GET_MEMBER_DESCRIPTORS));
        let own = monitor.descriptor(false);
        assert_eq!(own["properties"].as_array().unwrap().len(), 14);
        assert_eq!(own["events"], json!([]));
        let all = monitor.descriptor(true);
        assert_eq!(all["properties"].as_array().unwrap().len(), 14 + 3 + 1 + 8);
        assert_eq!(all["events"][0]["name"], "PropertyChanged");
        assert_eq!(all["methods"][0]["parameters"], json!([]));
        let set = &class(class::OBJECT).unwrap().descriptor(false)["methods"][1];
        assert_eq!(
            set["parameters"][1],
            json!({"description": null, "name": "value", "typeName": null,
            "isNullable": true, "isSequence": false, "constraints": null})
        );
        let touchpoints = class(class::OBJECT).unwrap().property(property::TOUCHPOINTS).unwrap();
        assert!(touchpoints.read_only && touchpoints.nullable && touchpoints.sequence);
        assert_eq!(known_class(&[1, 2, 2, 1, 0, 1]).unwrap().name, "NcReceiverMonitor");
        assert!(derives(&[1, 2, 2, 1, 0, 1], class::STATUS_MONITOR));
        assert!(!derives(class::WORKER, class::STATUS_MONITOR));
    }

    #[test]
    fn every_type_a_class_names_is_described() {
        let mut named: Vec<String> = Vec::new();
        for class in CLASSES {
            let descriptor = class.descriptor(false);
            for p in descriptor["properties"].as_array().unwrap() {
                named.extend(p["typeName"].as_str().map(String::from));
            }
            for m in descriptor["methods"].as_array().unwrap() {
                named.extend(m["resultDatatype"].as_str().map(String::from));
                for p in m["parameters"].as_array().unwrap() {
                    named.extend(p["typeName"].as_str().map(String::from));
                }
            }
        }
        for d in datatypes() {
            for f in d["fields"].as_array().into_iter().flatten() {
                named.extend(f["typeName"].as_str().map(String::from));
            }
            named.extend(d["parentType"].as_str().map(String::from));
        }
        for name in named {
            assert!(datatype(&name, false).is_some(), "{name} is not described");
        }
        let error = datatype("NcMethodResultError", true).unwrap();
        let fields: Vec<&str> =
            error["fields"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(fields, ["status", "errorMessage"]);
        assert_eq!(enum_name("NcLinkStatus", 2), Some("SomeDown"));
        assert_eq!(enum_name("NcSynchronizationStatus", 0), Some("NotUsed"));
        assert_eq!(enum_name("NcString", 0), None);
    }

    #[test]
    fn reads_touchpoints_and_element_ids() {
        let touchpoints = json!([touchpoint("receiver", "82fdc03f"), {"contextNamespace": "x-other", "resource": {}}]);
        assert_eq!(touchpoint_resources(&touchpoints), [("receiver", "82fdc03f")]);
        assert_eq!(ElementId::from_json(&json!({"level": 4, "index": 11})), Some(property::STREAM_STATUS));
        assert_eq!(ElementId::from_json(&json!({"level": -1, "index": 1})), None);
        let message = command(7, 1, method::GET, json!({"id": property::MEMBERS.json()}));
        assert_eq!(message["commands"][0]["methodId"], json!({"level": 1, "index": 1}));
    }
}
