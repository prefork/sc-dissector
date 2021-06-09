--------------------------------------------------------------------------------
-- BACnet Secure Connect Dissector for Wireshark (v0.1.0)
-- Copyright (C) 2020 Nate Benes
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--------------------------------------------------------------------------------

-- create a new protocol object for BACnet Secure Connect
bsc_protocol = Proto("bsc", "BACnet Secure Connect Protocol")

--
-- lookup tables
--
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

local accept_direct_connections = {
    [0] = "no", [1] = "yes"
}

local header_option_types = {
  [0] = "Reserved", [1] = "Secure Path", [2] = "Reserved", [3] = "Reserved",
  [4] = "Reserved", [5] = "Reserved", [6] = "Reserved", [7] = "Reserved",
  [8] = "Reserved", [9] = "Reserved", [10] = "Reserved", [11] = "Reserved",
  [12] = "Reserved", [13] = "Reserved", [14] = "Reserved", [15] = "Reserved",
  [16] = "Reserved", [17] = "Reserved", [18] = "Reserved", [19] = "Reserved",
  [20] = "Reserved", [21] = "Reserved", [22] = "Reserved", [23] = "Reserved",
  [24] = "Reserved", [25] = "Reserved", [26] = "Reserved", [27] = "Reserved",
  [28] = "Reserved", [29] = "Reserved", [30] = "Reserved", [31] = "Proprietary Option",
}

local ack_or_nak = {[0] = "ACK", [1] = "NAK"}

local conn_status = {
  [0] = "No Connection",
  [1] = "Connected to Primary",
  [2] = "Connected to Secondary"
}

--
-- field configuration
--
local fields = bsc_protocol.fields
fields.func             = ProtoField.uint8("bsc.function", "Function", base.HEX, bvlc_functions)
fields.cntl             = ProtoField.uint8("bsc.control", "Control", base.HEX)
fields.cntl_resrvedbits = ProtoField.uint8("bsc.control.reserved", "Reserved Bits", base.DEC, {[0] = "valid"}, 240)
fields.cntl_hasorigvmac = ProtoField.bool("bsc.control.has_orig_vmac", "Originating Virtual Address", 8, present_or_absent, 8)
fields.cntl_hasdestvmac = ProtoField.bool("bsc.control.has_dest_vmac", "Destination Virtual Address", 8, present_or_absent, 4)
fields.cntl_hasdestopts = ProtoField.bool("bsc.control.has_dest_opts", "Destination Options", 8, present_or_absent, 2)
fields.cntl_hasdataopts = ProtoField.bool("bsc.control.has_data_opts", "Data Options", 8, present_or_absent, 1)
fields.msgid            = ProtoField.uint16("bsc.message_id", "Message ID", base.HEX)
fields.origvmac         = ProtoField.ether("bsc.originating_vmac", "Originating Virtual Address")
fields.destvmac         = ProtoField.ether("bsc.destination_vmac", "Destination Virtual Address")
fields.dest_option      = ProtoField.none("bsc.destination_option", "Destination Option")
fields.data_option      = ProtoField.none("bsc.data_option", "Data Option")
fields.option_marker    = ProtoField.uint8("bsc.option.marker", "Header Marker", base.HEX)
fields.option_hasmore   = ProtoField.bool("bsc.option.has_more", "More Options", 8, yes_or_no, 128)
fields.option_mustund   = ProtoField.bool("bsc.option.must_understand", "Must Understand", 8, yes_or_no, 64)
fields.option_hasdata   = ProtoField.bool("bsc.option.has_data", "Header Data", 8, present_or_absent, 32)
fields.option_type      = ProtoField.uint8("bsc.option.type", "Type", base.HEX, header_option_types, 31)
fields.option_length    = ProtoField.uint8("bsc.option.length", "Length", base.DEC)
fields.option_data      = ProtoField.none("bsc.option.data", "Data")
fields.option_prop_vid  = ProtoField.uint16("bsc.option.vendor_id", "Vendor ID", base.DEC)
fields.option_prop_type = ProtoField.uint8("bsc.option.proprietary_type", "Type", base.DEC)
fields.option_prop_data = ProtoField.none("bsc.option.proprietary_data", "Data")
fields.payload          = ProtoField.none("bsc.payload", "Payload")

-- BVLC-result fields
fields.bvlcres_func     = ProtoField.uint8("bsc.bvlc_result.function", "Function", base.HEX, bvlc_functions)
fields.bvlcres_code     = ProtoField.uint8("bsc.bvlc_result.code", "Result", base.HEX, ack_or_nak)
fields.bvlcres_errmrk   = ProtoField.uint8("bsc.bvlc_result.error_marker", "Error Marker")
fields.bvlcres_errcls   = ProtoField.uint16("bsc.bvlc_result.error_class", "Error Class")
fields.bvlcres_errcde   = ProtoField.uint16("bsc.bvlc_result.error_code", "Error Code")
fields.bvlcres_errdet   = ProtoField.string("bsc.bvlc_result.error_details", "Error Details", base.UNICODE)

-- address resolution ACK fields
fields.addrres_uri      = ProtoField.string("bsc.address_resolution.uri", "WebSocket URI", base.UNICODE)

-- advertisement fields
fields.advrt_connstat   = ProtoField.uint8("bsc.advertisement.conn_status", "Hub Connection Status", base.HEX, conn_status)
fields.advrt_acceptdc   = ProtoField.uint8("bsc.advertisement.accepts_direct_connects", "Accepts Direct Connects", base.HEX, accept_direct_connections)
fields.advrt_maxbvlclen = ProtoField.uint16("bsc.advertisement.maximum_bvlc_len", "Maximum BVLC Length", base.DEC)
fields.advrt_maxnpdulen = ProtoField.uint16("bsc.advertisement.maximum_npdu_len", "Maximum NPDU Length", base.DEC)

-- connect request fields
fields.connreq_vmac       = ProtoField.ether("bsc.connect_request.vmac", "VMAC Address")
fields.connreq_uuid       = ProtoField.guid("bsc.connect_request.uuid", "Device UUID")
fields.connreq_maxbvlclen = ProtoField.uint16("bsc.connect_request.maximum_bvlc_len", "Maximum BVLC Length")
fields.connreq_maxnpdulen = ProtoField.uint16("bsc.connect_request.maximum_npdu_len", "Maximum NPDU Length")

-- connect accept fields
fields.connack_vmac       = ProtoField.ether("bsc.connect_accept.vmac", "VMAC Address")
fields.connack_uuid       = ProtoField.guid("bsc.connect_accept.uuid", "Device UUID")
fields.connack_maxbvlclen = ProtoField.uint16("bsc.connect_accept.maximum_bvlc_len", "Maximum BVLC Length")
fields.connack_maxnpdulen = ProtoField.uint16("bsc.connect_accept.maximum_npdu_len", "Maximum NPDU Length")

-- proprietary message fields
fields.proprietary_vid  = ProtoField.uint16("bsc.proprietary_message.vendor_id", "Vendor ID", base.DEC)
fields.proprietary_func = ProtoField.uint8("bsc.proprietary_message.function", "Function", base.DEC)
fields.proprietary_data = ProtoField.bytes("bsc.proprietary_message.data", "Proprietary Data")

-- resolve the NPDU dissector
bacnet_protocol = Dissector.get("bacnet")

--
-- header dissectors
--

local function dissect_header_options(buffer, root, field)
  local offset = 0
  while true do
    -- create a tree entry to glue this option together
    local tree = root:add(field)
    local hflags = buffer(offset, 1):uint()
    local htype = bit.band(hflags, 31)
    local hname = header_option_types[htype]
    tree:append_text(" (" .. hname .. ")")

    -- header marker is always present
    local marker = tree:add(fields.option_marker, buffer(offset, 1))
    marker:add(fields.option_hasmore, buffer(offset, 1))
    marker:add(fields.option_mustund, buffer(offset, 1))
    marker:add(fields.option_hasdata, buffer(offset, 1))
    marker:add(fields.option_type, buffer(offset, 1))

    -- length and data fields are conditional
    if bit.band(hflags, 32) == 32 then
      local length = buffer(offset + 1, 2):uint()
      tree:add(fields.option_length, buffer(offset + 1, 2))
      local data = tree:add(fields.option_data, buffer(offset + 2, length))
      if htype == 31 then
        -- proprietary option
        data:add(fields.option_prop_vid, buffer(offset + 3, 2))
        data:add(fields.option_prop_type, buffer(offset + 4, 1))
        data:add(fields.option_prop_data, buffer(offset + 5, length - 3))
      end
      offset = offset + 2 + length
    end
    offset = offset + 1

    -- bail out if no more header options
    if bit.band(hflags, 128) ~= 128 then
      break
    end
  end
  return offset
end

--
-- payload dissectors
--

local function format_vmac(buffer)
  return string.format(
    "%02x:%02x:%02x:%02x:%02x:%02x",
    buffer(0, 1):uint(), buffer(1, 1):uint(), buffer(2, 1):uint(),
    buffer(3, 1):uint(), buffer(4, 1):uint(), buffer(5, 1):uint()
  )
end

local function format_uuid(buffer)
  -- Wireshark's Tvb structure doesn't support 6-byte uints
  return string.format("%08x-%04x-%04x-%04x-%04x%02x",
    buffer(0, 4):uint(), buffer(4, 2):uint(), buffer(6, 2):uint(),
    buffer(8, 2):uint(), buffer(10, 4):uint(), buffer(14, 2):uint()
  )
end

local function dissect_bvlc_result(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (BVLC-Result)")
  tree:add(fields.bvlcres_func, payload(0, 1))
  tree:add(fields.bvlcres_code, payload(1, 1))
  if payload:len() > 2 then
    tree:add(fields.bvlcres_errmrk, payload(2, 1))
    tree:add(fields.bvlcres_errcls, payload(3, 2))
    tree:add(fields.bvlcres_errcde, payload(5, 2))
  end
  -- AB.2.4.1 "Can be an empty string using no octets."
  if payload:len() > 7 then
    tree:add(fields.bvlcres_errdet, payload(7))
  end
  local fn_str = bvlc_functions[payload(0, 1):uint()]
  return string.format("BVLC-Result (fn=%s,code=%d)", fn_str, payload(1, 1):uint())
end

local function dissect_address_resolution(payload, root)
  return "Address-Resolution"
end

local function dissect_address_resolution_ack(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (Address-Resolution-ACK)")
  local mark = 0
  for idx = 0, payload:len() do
    if payload(idx, 1):uint() == 0x20 then
      tree:add(fields.addrres_uri, payload(mark, idx - mark))
      mark = idx
    end
  end
  if mark > 0 then
    local len = payload:len()
    tree:add(fields.addrres_uri, payload(mark, len - mark))
  end
  return "Address-Resolution-ACK"
end

local function dissect_advertisement(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (Advertisement)")
  tree:add(fields.advrt_connstat, payload(0, 1))
  tree:add(fields.advrt_acceptdc, payload(1, 1))
  tree:add(fields.advrt_maxbvlclen, payload(2, 2))
  tree:add(fields.advrt_maxnpdulen, payload(4, 2))
  return string.format("Advertisement (connstat=%d,acceptdc:%d)", payload(0, 1):uint(), payload(1, 1):uint())
end

local function dissect_advertisement_solicitation(payload, root)
  return "Advertisement-Solicitation"
end

local function dissect_connect_request(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (Connect-Request)")
  tree:add(fields.connreq_vmac, payload(0, 6))
  tree:add(fields.connreq_uuid, payload(6, 16))
  tree:add(fields.connreq_maxbvlclen, payload(22, 2))
  tree:add(fields.connreq_maxnpdulen, payload(24, 2))
  local vmac = format_vmac(payload(0, 6))
  local uuid = format_uuid(payload(6, 16))
  return string.format("Connect-Request (vmac=%s,uuid=%s)", vmac, uuid)
end

local function dissect_connect_accept(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (Connect-Accept)")
  tree:add(fields.connack_vmac, payload(0, 6))
  tree:add(fields.connack_uuid, payload(6, 16))
  tree:add(fields.connack_maxbvlclen, payload(22, 2))
  tree:add(fields.connack_maxnpdulen, payload(24, 2))
  local vmac = format_vmac(payload(0, 6))
  local uuid = format_uuid(payload(6, 16))
  return string.format("Connect-Accept (vmac=%s,uuid=%s)", vmac, uuid)
end

local function dissect_disconnect_request(payload, root)
  return "Disconnect-Request"
end

local function dissect_disconnect_accept(payload, root)
  return "Disconnect-ACK"
end

local function dissect_heartbeat_request(payload, root)
  return "Heartbeat-Request"
end

local function dissect_heartbeat_ack(payload, root)
  return "Heartbeat-ACK"
end

local function dissect_proprietary_message(payload, root)
  local tree = root:add(fields.payload, payload)
  tree:append_text(" (Proprietary-Message)")
  tree:add(fields.proprietary_vid, payload(0, 2))
  tree:add(fields.proprietary_func, payload(2, 1))
  tree:add(fields.proprietary_data, payload(3))
  return string.format("Proprietary-Message (vendor_id=%d,function=%d)",
    payload(0, 2):uint(), payload(2, 1):uint())
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
  root:add(fields.func, buffer(0, 1))
  local cntl_tree = root:add(fields.cntl, buffer(1, 1))
  cntl_tree:add(fields.cntl_resrvedbits, buffer(1, 1))
  cntl_tree:add(fields.cntl_hasorigvmac, buffer(1, 1))
  cntl_tree:add(fields.cntl_hasdestvmac, buffer(1, 1))
  cntl_tree:add(fields.cntl_hasdestopts, buffer(1, 1))
  cntl_tree:add(fields.cntl_hasdataopts, buffer(1, 1))
  root:add(fields.msgid, buffer(2, 2))

  -- variable header
  local offset = 4
  local cntl_flags = buffer(1, 1):uint()
  if bit.band(cntl_flags, 8) == 8 then
    root:add(fields.origvmac, buffer(offset, 6))
    offset = offset + 6
  end
  if bit.band(cntl_flags, 4) == 4 then
    root:add(fields.destvmac, buffer(offset, 6))
    offset = offset + 6
  end
  if bit.band(cntl_flags, 2) == 2 then
    offset = offset + dissect_header_options(buffer(offset), root, fields.dest_option)
  end
  if bit.band(cntl_flags, 1) == 1 then
    offset = offset + dissect_header_options(buffer(offset), root, fields.data_option)
  end

  -- setup payload
  local bvlc_fn = buffer(0, 1):uint()
  local payload = buffer:range(offset)
  if bvlc_fn == 1 then
    -- delegate to the built-in NPDU dissector
    bacnet_protocol:call(payload:tvb(), pinfo, tree)
    return
  end

  -- handle link layer messages
  if     bvlc_fn == 0 then
    pinfo.cols.info = dissect_bvlc_result(payload, root)
  elseif bvlc_fn == 2 then
    pinfo.cols.info = dissect_address_resolution(payload, root)
  elseif bvlc_fn == 3 then
    pinfo.cols.info = dissect_address_resolution_ack(payload, root)
  elseif bvlc_fn == 4 then
    pinfo.cols.info = dissect_advertisement(payload, root)
  elseif bvlc_fn == 5 then
    pinfo.cols.info = dissect_advertisement_solicitation(payload, root)
  elseif bvlc_fn == 6 then
    pinfo.cols.info = dissect_connect_request(payload, root)
  elseif bvlc_fn == 7 then
    pinfo.cols.info = dissect_connect_accept(payload, root)
  elseif bvlc_fn == 8 then
    pinfo.cols.info = dissect_disconnect_request(payload, root)
  elseif bvlc_fn == 9 then
    pinfo.cols.info = dissect_disconnect_accept(payload, root)
  elseif bvlc_fn == 10 then
    pinfo.cols.info = dissect_heartbeat_request(payload, root)
  elseif bvlc_fn == 11 then
    pinfo.cols.info = dissect_heartbeat_ack(payload, root)
  elseif bvlc_fn == 12 then
    pinfo.cols.info = dissect_proprietary_message(payload, root)
  end
end

-- register the dissector
local ws_protocol_table = DissectorTable.get("ws.protocol")
ws_protocol_table:add("hub.bsc.bacnet.org", bsc_protocol)
ws_protocol_table:add("dc.bsc.bacnet.org", bsc_protocol)
