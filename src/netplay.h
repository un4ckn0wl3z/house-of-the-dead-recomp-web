// Online play (lockstep) and the determinism helpers it needs. See netplay.c and references/multiplayer.md.
#pragma once
#include <stdint.h>

enum { NET_OFF, NET_HOST, NET_GUEST, NET_TEST };
#define NET_MAX_PLAYERS 4

extern int net_mode;          // NET_OFF: normal play; NET_TEST: native determinism test (virtual clock, checksums)
extern int net_local;         // this player's slot (0 = host)
extern int net_skip_render;   // set while a guest catches up: frames are simulated without drawing

void net_init(void);
uint32_t net_clock(void);     // timeGetTime() while online: derived from the frame number
uint32_t net_tact(void);      // frames simulated since start (every mode)
int net_pending(void);        // guest: input bundles received and not yet simulated
int net_view_slot(void);      // whose camera this client draws (the local player; NET_TEST: PORT_NET_VIEW)
void net_stack_save(void);    // keep host-side calls into game code outside the frame from leaving traces on the
void net_stack_restore(void); // guest stack (game code may read stack locals it never set)
void net_cow_begin(void);     // start a pass whose guest memory writes are undone by net_cow_end()
void net_cow_end(void);

// The game's frame hook (game.c) calls these around the engine's frame function: net_frame_begin() before it
// (advances the clock), net_after_pump() after its message pump and before any game logic reads input.
void net_frame_begin(void);
void net_after_pump(void);

// A guest's input as it travels: buttons/keys as the engine's input flags, the cursor in WORLD coordinates
// (converted with the guest's own camera), and one key press.
typedef struct { uint32_t flags; float wx, wy; uint8_t chr, key, pad[2]; } NetInput;
// type 1 = join, 2 = leave; data: game-defined (e.g. the guest's loadout), applied identically on every client
typedef struct { uint8_t type, slot; char name[30]; uint8_t data[44]; } NetEvent;

// ---- provided by the game (src/game.c) ----
uint32_t port_input_block(uint32_t *size);              // guest address + size of the engine's input state
void port_net_join(int slot, const char *name, const uint8_t data[44]);   // run at the same frame everywhere
void port_net_leave(int slot);
void port_net_input(int slot, const NetInput *in);      // this frame's input for guest `slot`
uint32_t port_state_crc(uint32_t h);                    // mix the game's state into a checksum (crc_mix)
void port_view_camera(int slot, float *x, float *y);    // camera top-left of the view last drawn for `slot`
int port_bot_input(int slot, NetInput *in);             // native tests: a scripted bot's input (0 = none)
uint32_t crc_mix(uint32_t h, uint32_t v);
