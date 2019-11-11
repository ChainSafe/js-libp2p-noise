import protobuf from "protobufjs";
import * as crypto from 'libp2p-crypto';
import { ed25519 } from 'bcrypto';
import { bytes } from "../src/types/basic";

export async function loadPayloadProto () {
  const payloadProtoBuf = await protobuf.load("protos/payload.proto");
  return payloadProtoBuf.lookupType("pb.NoiseHandshakePayload");
}

export async function generateEd25519Keys() {
  return await crypto.keys.generateKeyPair('ed25519');
}

export async function signPayload(privateKey: bytes, payload: bytes) {
  const Ed25519PrivateKey = crypto.keys.supportedKeys.ed25519.Ed25519PrivateKey;
  // const ed25519 = Ed25519PrivateKey(privateKey, "need-to-get-public-key");
  // return ed25519.sign(privateKey, payload);
}
