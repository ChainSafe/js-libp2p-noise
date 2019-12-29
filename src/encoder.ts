import {Buffer} from "buffer";
import {bytes} from "./@types/basic";
import {MessageBuffer} from "./@types/handshake";

export const uint16BEEncode = (value, target, offset) => {
  target = target || Buffer.allocUnsafe(2);
  return target.writeUInt16BE(value, offset);
};
uint16BEEncode.bytes = 2;

export const uint16BEDecode = data => {
  if (data.length < 2) throw RangeError('Could not decode int16BE');
  return data.readUInt16BE(0);
};
uint16BEDecode.bytes = 2;

export function encodeMessageBuffer(message: MessageBuffer): bytes {
  return Buffer.concat([message.ne, message.ns, message.ciphertext]);
}

export function decodeMessageBuffer(message: bytes): MessageBuffer {
  return {
    ne: message.slice(0, 32),
    ns: message.slice(32, 64),
    ciphertext: message.slice(64, message.length),
  }
}
