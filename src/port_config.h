// Per-game settings: The House of the Dead (PC, Sega 1998, Watcom C/C++ 10.x).
#pragma once

#define GAME_EXE        "THOTD.EXE"
#define GAME_TITLE      "The House of the Dead"
#define GAME_DIR_ENV    "GAME_DIR"
// The image spans 0x400000-0x13F0000 (7 MB data + 7 MB bss); the guest heap starts above it.
#define IMAGE_END       0x01400000u
#ifndef GUEST_SIZE_MB
#define GUEST_SIZE_MB   96
#endif
