# Major work in process
# need to figure out how to parse the bytes to get the ACLs
# to get if an object is protected from accidental deletion
# and to change this flag
import struct

offset_owner = struct.unpack("<I", sd_bytes[4:8])[0]
offset_group = struct.unpack("<I", sd_bytes[8:12])[0]
offset_sacl = struct.unpack("<I", sd_bytes[12:16])[0]
offset_dacl = struct.unpack("<I", sd_bytes[16:20])[0]
bytes_owner = sd_bytes[offset_owner:offset_group]
bytes_group = sd_bytes[offset_group:offset_sacl]
bytes_sacl = sd_bytes[offset_sacl:offset_dacl]
bytes_dacl = sd_bytes[offset_dacl:]