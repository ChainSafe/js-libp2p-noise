import protobuf from "protobufjs";
import * as crypto from 'libp2p-crypto';
import { ed25519 } from 'bcrypto';

export async function loadPayloadProto () {
  const payloadProtoBuf = await protobuf.load("protos/payload.proto");
  return payloadProtoBuf.lookupType("pb.NoiseHandshakePayload");
}

export async function generateEd25519Keys() {
  return await crypto.keys.generateKeyPair('ed25519');
}
