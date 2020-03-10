//
// Copyright (C) 2020 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <iconv.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <err.h>
#include <mcheck.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "log.h"
#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"

#define xstr(s) str(s)
#define str(s) #s

// In order to get output from scripts, I hook window.parseInt(), and check if
// the first character of the string is the magic (UTF-16LE) character.
// this little snippet makes that available as console.log().
#define CONSOLE_LOG_MAGIC 0x4141

const char header[] =
    "var console = {                                                        \n"
    "   log: function() {                                                   \n"
    "       parseInt(String.fromCharCode(" xstr(CONSOLE_LOG_MAGIC) ")       \n"
    "           + Array.prototype.join.call(arguments, ' ')                 \n"
    "           + String.fromCharCode(0));                                  \n"
    "   }                                                                   \n"
    "};";

// This structure appears to be 0xF4 bytes, used to configure the interpreter
// object. I just accept most of the defaults, a few fields must be set. The
// size must be exact, because it's passed *by value* to the routine at
// 0x636930C0 (i.e. not by reference), and it's a callee-clears function.
typedef struct _JSINT_PARAMS {
    BYTE field_0[160];
    DWORD field_A0;
    DWORD field_A4;
    DWORD field_A8;
    DWORD field_AC;
    DWORD field_B0;
    PVOID field_B4;
    DWORD field_B8;
    DWORD field_BC;
    DWORD field_C0;
    DWORD field_C4;
    DWORD field_C8;
    PVOID field_CC;
    DWORD field_D0;
    DWORD field_D4;
    DWORD field_D8;
    DWORD field_DC;
    DWORD field_E0;
    DWORD field_E4;
    DWORD field_E8;
    DWORD field_EC;
    DWORD field_F0;
} JSINT_PARAMS, *PJSINT_PARAMS;

PVOID (* engine_GlobalStart)(PVOID callback, DWORD unknown);

// These addresses are from algo.dll with hash D357DD90BDD1E597E417791851F591BD
PVOID (* __thiscall jsint_constructor)(PVOID this, DWORD unused) = (PVOID) 0x636923B0;
BOOL (* __thiscall jsint_init)(PVOID this, JSINT_PARAMS params) = (PVOID) 0x636930C0;
DWORD (* __thiscall jsint_run)(PVOID this, PVOID inputbuf, DWORD inputlen, DWORD unknown, DWORD flag) = (PVOID) 0x63693F00;
PVOID (* __cdecl window_parseInt)(void) = (PVOID) 0x637810D0;

struct jsstr {
    DWORD field_0;
    DWORD field_4;
    DWORD field_8;
    DWORD field_C;
    DWORD field_10;
    DWORD field_14;
    DWORD field_18;
    DWORD field_1C;
    DWORD field_20;
    DWORD field_24;
    DWORD field_28;
    DWORD field_2C;
    struct {
        struct {
            PWCHAR (__thiscall *GetStringValue)(PVOID this);
        } *vtbl;
    } data;
};

struct jsval {
    DWORD type;
    union {
        BYTE boolean;
        struct jsstr *string;
        double number;
    } value;
};

struct arguments {
    struct jsval *arglist;
    DWORD numargs;
};


// I inject this routine into window.parseInt, if the first character of the
// string is the magic character %u4141, I assume it was a log message and
// convert it to UTF-8 and print it.
//
// When this routine returns, control returns to window.parseInt.
void interpreter_hook_point(uintptr_t retaddr,
                            struct jsval **retval,
                            struct arguments *args,
                            PVOID thisobj,
                            PVOID jsint)
{
    static iconv_t cd;
    size_t lenparam = 0;
    size_t lenout = 0;
    struct jsstr *param;
    PWCHAR paramstr;
    char *outptr;
    char *output;

    void __attribute__((constructor)) init()
    {
        cd = iconv_open("UTF-8", "UTF-16LE");
    }

    void __attribute__((destructor)) fini()
    {
        iconv_close(cd);
    }

    if (args->numargs != 1)
        return;

    if (args->arglist[0].type != 1)
        return;

    param = args->arglist[0].value.string;

    // First resolve the parameter address.
    paramstr = param->data.vtbl->GetStringValue(&param->data);

    // Verify this message is for us, by checking for magic character.
    if (*paramstr++ != CONSOLE_LOG_MAGIC)
        return;

    // It is for us, count the number of widechars provided.
    while (paramstr[lenparam++])
        ;

    // Allocate space for output string.
    outptr = memset(alloca(lenparam), 0, lenparam);
    output = outptr;
    lenout = lenparam;

    // Adjust input size for UTF-16 characters.
    lenparam *= sizeof(*paramstr);

    // Now convert to UTF-8.
    iconv(cd, (void *)(&paramstr), &lenparam, &outptr, &lenout);

    // Log result.
    printf("%s\n", output);
    return;
}

PVOID resolve_callback_code(DWORD callback_code)
{
    switch (callback_code) {
        case 'CLMR': return malloc;
        case 'ERFR': return free;
    }

    // It requests dozens of functions, but we don't need most of them.
    return NULL;
}

int main(int argc, char **argv, char **envp)
{
    BOOL result;
    PVOID jsint;
    JSINT_PARAMS jsparams = {
        .field_A0 = ~0,
        .field_B4 = "",
        .field_CC = "",
    };
    struct pe_image image = {
        .name   = "algo.dll",
    };

    // Enable pedantic heap checking.
    mcheck_pedantic(0);

    // Load the scan engine.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        return 1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    if (get_export("engine_GlobalStart", &engine_GlobalStart)) {
        LogMessage("failed to resolve required module exports");
        return 1;
    }

    // Call DllMain()
    image.entry((PVOID) 'ALGO', DLL_PROCESS_ATTACH, NULL);

    // It's not important if this succeeds, just need to initialize callbacks.
    engine_GlobalStart(resolve_callback_code, 0);

    // Allocate interpreter object, you can see this allocation in the function
    // at 634D7AE0.
    jsint = calloc(1, 0x54A0);

    // Hook Window::parseInt so we can get some output.
    if (insert_function_redirect(window_parseInt,
                                 interpreter_hook_point,
                                 HOOK_DEFAULT) == false) {
        LogMessage("Failed to hook window.parseInt(), wont be able to display output");
    }

    // Check if user wants a file or a shell..
    if (argc > 1) {
        size_t filelen;
        char *filebuf;
        FILE *script;

        // The first parameter is the filename to read.
        script = fopen(argv[1], "r");

        if (script == NULL) {
            err(EXIT_FAILURE, "The specified script could not be found");
        }

        // Seek to the end of the input.
        fseek(script, 0, SEEK_END);

        // Allocate space to store the script.
        filelen = ftell(script);
        filebuf = calloc(filelen + sizeof(header), 1);

        rewind(script);

        if (filebuf == NULL) {
            err(EXIT_FAILURE, "Memory allocation failed");
        }

        // Prepend the header and read data.
        if (fread(mempcpy(filebuf, header, strlen(header)),
                  1,
                  filelen,
                  script) != filelen) {
            err(EXIT_FAILURE, "Failed to read the script specified");
        }

        LogMessage("File `%s` loaded, about to initialize interpreter...", argv[1]);

        // This creates the class object we need to start the interpreter.
        jsint = jsint_constructor(jsint, 0);
        jsint_init(jsint, jsparams);
        jsint_run(jsint, filebuf, filelen + sizeof(header), 0, true);
        return 0;
    }

    LogMessage("Ready, type javascript (history available, use arrow keys)");
    LogMessage("Use `console.log()` to show output, use ^D to exit");

    while (true) {
        char *inputline = readline("> ");
        char *scanbuf;
        int result;

        if (inputline) {
            char *escapebuf = calloc(strlen(inputline) + 1, 3);
            char *p = escapebuf;

            if (!escapebuf)
                break;

            // This is probably not correct.
            for (size_t i = 0; inputline[i]; i++) {
               if (inputline[i] == '%') {
                   *p++ = '%'; *p++ = '2'; *p++ = '5';
               } else if (inputline[i] == '\'') {
                   *p++ = '%'; *p++ = '2'; *p++ = '7';
               } else if (inputline[i] == '\\') {
                   *p++ = '%'; *p++ = '5'; *p++ = 'c';
               } else {
                   *p++ = inputline[i];
               }
            }

            if (asprintf(&scanbuf,
                         "%s                                    \n"
                         "try {                                 \n"
                         "  console.log(eval(unescape('%s')));  \n"
                         "} catch (e) {                         \n"
                         "  console.log('Exception: ' + e);     \n"
                         "}                                     \n",
                         header,
                         escapebuf) == -1) {
                err(EXIT_FAILURE, "memory allocation failure");
            }

            free(escapebuf);
        } else {
            break;
        }

        jsint = jsint_constructor(jsint, 0);

        jsint_init(jsint, jsparams);

        result = jsint_run(jsint, scanbuf, strlen(scanbuf), 0, true);

        add_history(inputline);
        free(scanbuf);
        free(inputline);

        if (result < 0) {
            DebugLog("-> %#x (interpreter failure)", result);
            break;
        }
    }

    return 0;
}

