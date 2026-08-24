# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for zForth (zevv/zForth) -- a tiny embeddable Forth interpreter in C.
# Builds on top of the org C/C++ base image (clang/llvm + libFuzzer/afl++ already present).

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV -- an empty
# value breaks clang both here and for any in-image rebuild. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Undefaulted (no '=') so the base ENV flows through when not passed, and an explicit
# --build-arg SANITIZER_FLAGS="..." overrides it.
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
