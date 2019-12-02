import { x25519, ed25519 } from 'bcrypto';
import protobuf from "protobufjs";
import { Buffer } from "buffer";
import debug from "debug";

import { KeyPair } from "./@types/libp2p";
import { bytes } from "./@types/basic";
import { MessageBuffer } from "./xx";

export const logger = debug('libp2p:noise');

export async function loadPayloadProto () {
  const payloadProtoBuf = await protobuf.load("protos/payload.proto");
  return payloadProtoBuf.lookupType("pb.NoiseHandshakePayload");
}

export function generateKeypair(): KeyPair {
  const privateKey = x25519.privateKeyGenerate();
  const publicKey = x25519.publicKeyCreate(privateKey);

  return {
    publicKey,
    privateKey,
  }
}

export async function createHandshakePayload(
  libp2pPublicKey: bytes,
  libp2pPrivateKey: bytes,
  signedPayload: bytes,
  signedEarlyData?: EarlyDataPayload,
): Promise<bytes> {
  const NoiseHandshakePayload = await loadPayloadProto();
  const earlyDataPayload = signedEarlyData ?
    {
      libp2pData: signedEarlyData.libp2pData,
      libp2pDataSignature: signedEarlyData.libp2pDataSignature,
    } : {};

  const payloadInit = NoiseHandshakePayload.create({
    libp2pKey: libp2pPublicKey,
    noiseStaticKeySignature: signedPayload,
    ...earlyDataPayload,
  });

  return Buffer.from(NoiseHandshakePayload.encode(payloadInit).finish());
}


export function signPayload(libp2pPrivateKey: bytes, payload: bytes) {
  return ed25519.sign(payload, libp2pPrivateKey);
}

type EarlyDataPayload = {
  libp2pData: bytes;
  libp2pDataSignature: bytes;
}

export function signEarlyDataPayload(libp2pPrivateKey: bytes, earlyData: bytes): EarlyDataPayload {
  const payload = getEarlyDataPayload(earlyData);
  const signedPayload = signPayload(libp2pPrivateKey, payload);

  return {
    libp2pData: payload,
    libp2pDataSignature: signedPayload,
  }
}

export const getHandshakePayload = (publicKey: bytes ) => Buffer.concat([Buffer.from("noise-libp2p-static-key:"), publicKey]);

export const getEarlyDataPayload = (earlyData: bytes) => Buffer.concat([Buffer.from("noise-libp2p-early-data:"), earlyData]);

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

export const int16BEEncode = (value, target, offset) => {
  target = target || Buffer.allocUnsafe(2);
  return target.writeInt16BE(value, offset);
};
int16BEEncode.bytes = 2;

export const int16BEDecode = data => {
  if (data.length < 2) throw RangeError('Could not decode int16BE');
  return data.readInt16BE(0);
};
int16BEDecode.bytes = 2;
