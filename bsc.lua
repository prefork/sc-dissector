-------------------------------------------------------------------------------
--
-- BACnet Secure Connect Protocol Dissector for Wireshark
--
-------------------------------------------------------------------------------

-- create a new protocol object for BACnet Secure Connect
bsc_protocol = Proto("bsc", "BACnet Secure Connect Protocol")

-- lookup tables
local bvlc_functions = {
  [0] = "BVLC-Result", [1] = "Encapsulated-NPDU",
  [2] = "Address-Resolution", [3] = "Address-Resolution-ACK",
  [4] = "Advertisement", [5] = "Advertisement-Solicitation",
  [6] = "Connect-Request", [7] = "Connect-Accept",
  [8] = "Disconnect-Request", [9] = "Disconnect-Accept",
  [10] = "Heartbeat-Request", [11] = "Heartbeat-ACK",
  [12] = "Proprietary-Message"
}

local present_or_absent = {
  "present", "absent"
}

local yes_or_no = {
  "yes", "no"
}

local header_option_types = {
  [0] = "Reserved", [1] = "Secure Path", [2] = "Reserved", [3] = "Reserved",
  [4] = "Reserved", [5] = "Reserved", [6] = "Reserved", [7] = "Reserved",
  [8] = "Reserved", [9] = "Reserved", [10] = "Reserved", [11] = "Reserved",
  [12] = "Reserved", [13] = "Reserved", [14] = "Reserved", [15] = "Reserved",
  [16] = "Reserved", [17] = "Reserved", [18] = "Reserved", [19] = "Reserved",
  [20] = "Reserved", [21] = "Reserved", [22] = "Reserved", [23] = "Reserved",
  [24] = "Reserved", [25] = "Reserved", [26] = "Reserved", [27] = "Reserved",
  [28] = "Reserved", [29] = "Reserved", [30] = "Reserved", [31] = "Proprietary-Message",
}

local ack_or_nak = {[0] = "ACK", [1] = "NAK"}

-- common fields
fld_func             = ProtoField.uint8("bsc.function", "Function", base.HEX, bvlc_functions)
fld_cntl             = ProtoField.uint8("bsc.control", "Control", base.HEX)
fld_cntl_resrvedbits = ProtoField.uint8("bsc.control.reserved", "Reserved Bits", base.DEC, {[0] = "valid"}, 240)
fld_cntl_hasorigvmac = ProtoField.bool("bsc.control.has_orig_vmac", "Originating Virtual Address", 8, present_or_absent, 8)
fld_cntl_hasdestvmac = ProtoField.bool("bsc.control.has_dest_vmac", "Destination Virtual Address", 8, present_or_absent, 4)
fld_cntl_hasdestopts = ProtoField.bool("bsc.control.has_dest_opts", "Destination Options", 8, present_or_absent, 2)
fld_cntl_hasdataopts = ProtoField.bool("bsc.control.has_data_opts", "Data Options", 8, present_or_absent, 1)
fld_msgid            = ProtoField.uint16("bsc.msg_id", "Message ID", base.HEX)
fld_origvmac         = ProtoField.ether("bsc.orig_vmac", "Originating Virtual Address")
fld_destvmac         = ProtoField.ether("bsc.dest_vmac", "Destination Virtual Address")
fld_destopts         = ProtoField.none("bsc.destopts", "Destination Options")
fld_dataopts         = ProtoField.none("bsc.dataopts", "Data Options")
fld_option_marker    = ProtoField.none("bsc.option.marker", "Header Flags")
fld_option_hasmore   = ProtoField.bool("bsc.option.has_more", "More Options", 8, yes_or_no, 128)
fld_option_mustund   = ProtoField.bool("bsc.option.must_understand", "Must Understand", 8, yes_or_no, 64)
fld_option_hasdata   = ProtoField.bool("bsc.option.has_data", "Header Data", 8, present_or_absent, 32)
fld_option_type      = ProtoField.uint8("bsc.option.type", "Type", base.HEX, header_option_types, 31)
fld_option_length    = ProtoField.uint8("bsc.option.length", "Length", base.DEC)
fld_option_data      = ProtoField.none("bsc.option.data", "Data")
fld_option_secure    = ProtoField.none("bsc.option.secure", "Secure Path")
fld_option_prop      = ProtoField.none("bsc.option.prop", "Proprietary Option")
fld_option_prop_vid  = ProtoField.uint16("bsc.option.prop.vendor_id", "Function", base.DEC)
fld_option_prop_type = ProtoField.uint8("bsc.option.prop.type", "Type", base.DEC)
fld_option_prop_data = ProtoField.none("bsc.option.prop.data", "Data")
fld_payload          = ProtoField.bytes("bsc.payload", "Payload")

-- BVLC-result fields
fld_bvlcres_func     = ProtoField.uint8("bsc.bvlc_result.function", "Function", base.HEX, bvlc_functions)
fld_bvlcres_code     = ProtoField.uint8("bsc.bvlc_result.code", "Result", base.HEX, ack_or_nak)
fld_bvlcres_errmrk   = ProtoField.uint8("bsc.bvlc_result.error_marker", "Error Marker")
fld_bvlcres_errcls   = ProtoField.uint16("bsc.bvlc_result.error_class", "Error Class")
fld_bvlcres_errcde   = ProtoField.uint16("bsc.bvlc_result.error_code", "Error Code")
fld_bvlcres_errdet   = ProtoField.string("bsc.bvlc_result.error_details", "Error Details", base.UNICODE)

-- connect request fields
fld_connreq_vmac     = ProtoField.ether("bsc.conn_req.vmac", "VMAC Address")
fld_connreq_uuid     = ProtoField.guid("bsc.conn_req.uuid", "UUID")
fld_connreq_bvlclen  = ProtoField.uint16("bsc.conn_req.bvlc_len", "Maximum BVLC Length Accepted")
fld_connreq_npdulen  = ProtoField.uint16("bsc.conn_req.npdu_len", "Maximum NPDU Length Accepted")

-- connect accept fields
fld_connack_vmac     = ProtoField.ether("bsc.conn_ack.vmac", "VMAC Address")
fld_connack_uuid     = ProtoField.guid("bsc.conn_ack.uuid", "UUID")
fld_connack_bvlclen  = ProtoField.uint16("bsc.conn_ack.bvlc_len", "Maximum BVLC Length Accepted")
fld_connack_npdulen  = ProtoField.uint16("bsc.conn_ack.npdu_len", "Maximum NPDU Length Accepted")

-- wire up the fields
bsc_protocol.fields = {
  fld_func, fld_cntl, fld_cntl_hasdataopts, fld_cntl_hasdestopts,
  fld_cntl_hasdestvmac, fld_cntl_hasorigvmac, fld_cntl_resrvedbits,
  fld_msgid, fld_origvmac, fld_destvmac, fld_destopts, fld_dataopts,
  fld_option_marker, fld_option_hasmore, fld_option_mustund,
  fld_option_hasdata, fld_option_type, fld_option_length, fld_option_data,
  fld_option_secure, fld_option_prop, fld_option_prop_vid,
  fld_option_prop_type, fld_option_prop_data, fld_payload, fld_bvlcres_func,
  fld_bvlcres_code, fld_bvlcres_errmrk, fld_bvlcres_errcls, fld_bvlcres_errcde,
  fld_bvlcres_errdet, fld_connreq_vmac, fld_connreq_uuid, fld_connreq_bvlclen,
  fld_connreq_npdulen, fld_connack_vmac, fld_connack_uuid, fld_connack_bvlclen,
  fld_connack_npdulen
}

-- resolve the NPDU dissector
bacnet_protocol = Dissector.get("bacnet")

--
-- payload dissectors
--

local function dissect_bvlc_result(payload, tree)
  tree:add(fld_bvlcres_func, payload(0, 1))
  tree:add(fld_bvlcres_code, payload(1, 1))
  if payload:len() > 2 then
    tree:add(fld_bvlcres_errmrk, payload(2, 1))
    tree:add(fld_bvlcres_errcls, payload(3, 2))
    tree:add(fld_bvlcres_errcde, payload(5, 2))
    tree:add(fld_bvlcres_errdet, payload(7))
  end
  tree:append_text(" (BVLC-Result)")
  return "BVLC-Result"
end

local function dissect_address_resolution(payload, tree)
end

local function dissect_address_resolution_ack(payload, tree)
end

local function dissect_advertisement(payload, tree)
end

local function dissect_advertisement_solicitation(payload, tree)
end

local function dissect_connect_request(payload, tree)
  tree:add(fld_connreq_vmac, payload(0, 6))
  tree:add(fld_connreq_uuid, payload(6, 16))
  tree:add(fld_connreq_bvlclen, payload(22, 2))
  tree:add(fld_connreq_npdulen, payload(24, 2))
  tree:append_text(" (Connect-Request)")
  return "Connect-Request" -- TODO(nb): show vmac and uuid here
end

local function dissect_connect_accept(payload, tree)
  tree:add(fld_connack_vmac, payload(0, 6))
  tree:add(fld_connack_uuid, payload(6, 16))
  tree:add(fld_connack_bvlclen, payload(22, 2))
  tree:add(fld_connack_npdulen, payload(24, 2))
  tree:append_text(" (Connect-Accept)")
  return "Connect-Accept" -- TODO(nb): show vmac and uuid here
end

local function dissect_disconnect_request(payload, tree)
end

local function dissect_disconnect_accept(payload, tree)
end

local function dissect_heartbeat_request(payload, tree)
  tree:append_text(" (Heartbeat-Request)")
  return "Heartbeat-Request"
end

local function dissect_heartbeat_ack(payload, tree)
  tree:append_text(" (Heartbeat-ACK)")
  return "Heartbeat-ACK"
end

local function dissect_proprietary_message(payload, root)
end

--
-- pdu dissector
--
function bsc_protocol.dissector(buffer, pinfo, tree)
  -- we need at least four bytes for func, cntl, and msgid
  local length = buffer:len()
  if length < 4 then return end

  -- link it up to the tree
  pinfo.cols.protocol = "BACnet/SC"
  local root = tree:add(bsc_protocol, buffer(), "Building Automation and Control Network LPDU")

  -- fixed header
  root:add(fld_func, buffer(0, 1))
  local cntl_tree = root:add(fld_cntl, buffer(1, 1))
  cntl_tree:add(fld_cntl_resrvedbits, buffer(1, 1))
  cntl_tree:add(fld_cntl_hasorigvmac, buffer(1, 1))
  cntl_tree:add(fld_cntl_hasdestvmac, buffer(1, 1))
  cntl_tree:add(fld_cntl_hasdestopts, buffer(1, 1))
  cntl_tree:add(fld_cntl_hasdataopts, buffer(1, 1))
  root:add(fld_msgid, buffer(2, 2))

  -- variable header
  local offset = 4
  local cntl_flags = buffer(1, 1):uint()
  if bit.band(cntl_flags, 8) == 8 then
    root:add(fld_origvmac, buffer(offset, 6))
    offset = offset + 6
  end
  if bit.band(cntl_flags, 4) == 4 then
    root:add(fld_destvmac, buffer(offset, 6))
    offset = offset + 6
  end

  -- setup payload
  local bvlc_fn = buffer(0, 1):uint()
  local payload = buffer:range(offset, length - offset):tvb()
  if bvlc_fn == 1 then
    bacnet_protocol:call(payload, pinfo, tree)
    return
  end

  -- handle link layer messages
  local pldtree = root:add(fld_payload, buffer:range(offset))
  if     bvlc_fn == 0 then
    pinfo.cols.info = dissect_bvlc_result(payload, pldtree)
  elseif bvlc_fn == 2 then
    pinfo.cols.info = dissect_address_resolution(payload, pldtree)
  elseif bvlc_fn == 3 then
    pinfo.cols.info = dissect_address_resolution_ack(payload, pldtree)
  elseif bvlc_fn == 4 then
    pinfo.cols.info = dissect_advertisement(payload, pldtree)
  elseif bvlc_fn == 5 then
    pinfo.cols.info = dissect_advertisement_solicitation(payload, pldtree)
  elseif bvlc_fn == 6 then
    pinfo.cols.info = dissect_connect_request(payload, pldtree)
  elseif bvlc_fn == 7 then
    pinfo.cols.info = dissect_connect_accept(payload, pldtree)
  elseif bvlc_fn == 8 then
    pinfo.cols.info = dissect_disconnect_request(payload, pldtree)
  elseif bvlc_fn == 9 then
    pinfo.cols.info = dissect_disconnect_accept(payload, pldtree)
  elseif bvlc_fn == 10 then
    pinfo.cols.info = dissect_heartbeat_request(payload, pldtree)
  elseif bvlc_fn == 11 then
    pinfo.cols.info = dissect_heartbeat_ack(payload, pldtree)
  elseif bvlc_fn == 12 then
    pinfo.cols.info = dissect_proprietary_message(payload, pldtree)
  end
end

-- register the dissector
local ws_protocol_table = DissectorTable.get("ws.protocol")
ws_protocol_table:add("hub.bsc.bacnet.org", bsc_protocol)
ws_protocol_table:add("dc.bsc.bacnet.org", bsc_protocol)
