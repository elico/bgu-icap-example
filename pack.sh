#!/usr/bin/env bash
echo "PACKING: `basename $PWD`.tar.xz"
tar cvfJ `basename $PWD`.tar.xz bin LICENSE

