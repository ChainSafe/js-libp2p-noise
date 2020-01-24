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

// Note: IK and XX encoder usage is opposite (XX uses in stages encode0 where IK uses encode1)

export function encode0(message: MessageBuffer): bytes {
  return Buffer.concat([message.ne, message.ciphertext]);
}

export function encode1(message: MessageBuffer): bytes {
  return Buffer.concat([message.ne, message.ns, message.ciphertext]);
}

export function decode0(input: bytes): MessageBuffer {
  if (input.length < 32) {
    throw new Error("Cannot decode stage 0 MessageBuffer: length less than 32 bytes.");
  }

  return {
    ne: input.slice(0, 32),
    ciphertext: input.slice(32, input.length),
    ns: Buffer.alloc(0),
  }
}

export function decode1(input: bytes): MessageBuffer {
  if (input.length < 96) {
    throw new Error("Cannot decode stage 0 MessageBuffer: length less than 96 bytes.");
  }

  return {
    ne: input.slice(0, 32),
    ns: input.slice(32, 64),
    ciphertext: input.slice(64, input.length),
  }
}
