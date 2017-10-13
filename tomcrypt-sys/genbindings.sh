#!/usr/bin/env bash
bindgen libtomcrypt/src/headers/tomcrypt.h -o src/bindings.rs -- -Ilibtomcrypt/src/headers -DUSE_TFM -DTFM_DESC -DLTC_SOURCE -DMECC_PF
