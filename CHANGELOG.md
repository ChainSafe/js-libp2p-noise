# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] -

### Bugfixes
- return handshake remote peer from secureOutbound
- fix browser usage of buffer

## [1.0.0-rc.8] - 2019-03-05

### Breaking changes
- Disabled noise pipes

### Bugfixes
- fixed empty ephemeral bug in XX
- verification of AEAD decryption


## [1.0.0-rc.7] - 2019-02-20

### Bugfixes
- attach/remove aead auth tag on cyphertext

## [1.0.0-rc.6] - 2019-02-20

### Bugfixes
- attach/remove aead auth tag on cyphertext
- better protobuf handling (static module generation)

## [1.0.0-rc.5] - 2019-02-10

### Bugfixes
- fix module compiling in node 10 (class properties)

## [1.0.0-rc4] - 2019-02-10

### Bugfixes
- resolved bug with key cache and null remote peer
- fixed IK flow as initiator and responder
