# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-10-08

### Changed

- Add a repository contact to the fixed versioned User-Agent sent on every broker-authorized GET; callers still cannot override it.
- Pin the provider SDK, testkit, and carried core crates exactly to 0.36.0 without changing the WIT imports or exports.

## [0.6.0] - 2026-10-04

### Changed

- Pin core SDK, testkit, and broker crates to 0.33.0; return to HTTP client 1.1.0 buffered `send` without new imports.
- Bound response bodies to the effective 256 KiB Pi GET/HEAD grant and refuse oversized bodies before stdout; large/streaming responses require a different asset-backed provider.

## [0.5.0] - 2026-10-03

### Changed

- Move to provider SDK 0.31.0 with typed invocation and broker-owned stdio streaming; preserve bounded GET authority and credential handling.
- Pin published core crates exactly at 0.31.0 for the release.

## [0.4.0] - 2026-09-20

### Changed

- Move to provider SDK 0.18.0 and HTTP interface 1.1.0; caller behavior is unchanged.
