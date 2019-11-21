import { x25519, ed25519 } from 'bcrypto';
import protobuf from "protobufjs";

import { KeyPair } from "./@types/libp2p";
import { bytes } from "./@types/basic";
import {Buffer} from "buffer";

export async function loadPayloadProto () {
  const payloadProtoBuf = await protobuf.load("protos/payload.proto");
  return payloadProtoBuf.lookupType("pb.NoiseHandshakePayload");
}

export async function generateKeypair() : Promise<KeyPair> {
  const privateKey = x25519.privateKeyGenerate();
  const publicKey = x25519.publicKeyCreate(privateKey);

  return {
    publicKey,
    privateKey,
  }
}

export async function createHandshakePayload(
  libp2pPublicKey: bytes,
  signedPayload: bytes,
  earlyData?: bytes,
  libp2pPrivateKey?: bytes,
) : Promise<bytes> {
  const NoiseHandshakePayload = await loadPayloadProto();
  const payloadInit = NoiseHandshakePayload.create({
    libp2pKey: libp2pPublicKey,
    noiseStaticKeySignature: signedPayload,
    ...resolveEarlyDataPayload(libp2pPrivateKey, earlyData),
  });

  return Buffer.from(NoiseHandshakePayload.encode(payloadInit).finish());
}


export function signPayload(privateKey: bytes, payload: bytes) {
  return ed25519.sign(payload, privateKey);
}

export const getHandshakePayload = (publicKey: bytes ) => Buffer.concat([Buffer.from("noise-libp2p-static-key:"), publicKey]);

export const getEarlyDataPayload = (earlyData: bytes) => Buffer.concat([Buffer.from("noise-libp2p-early-data:"), earlyData]);

function resolveEarlyDataPayload(privateKey?: bytes, earlyData?: bytes) : Object {
  if (!earlyData || !privateKey) {
    return {};
  }

  const payload = getEarlyDataPayload(earlyData);
  const signedPayload = signPayload(privateKey, payload);
  return {
    libp2pData: payload,
    libp2pDataSignature: signedPayload,
  }
}

