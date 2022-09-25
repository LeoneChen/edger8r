#!/bin/bash
# Only for debug usage
rm -rf _build
ocamlbuild -cflag -g -lflag -g -libs str,unix -pkgs yojson Edger8r.byte