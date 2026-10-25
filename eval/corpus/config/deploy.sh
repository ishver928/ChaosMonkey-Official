#!/bin/sh
curl -k https://internal.example.com/health # expect: CM-D007
export GITHUB_TOKEN=ghp_DEMOfakeTOKENnotREAL0000000000000000 # expect: CM-S003
curl https://internal.example.com/health
