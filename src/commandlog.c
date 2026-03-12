/*
 * Copyright (c) Valkey Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Commandlog implements a system that is able to remember the latest N
 * queries that took more than M microseconds to execute, or consumed
 * too much network bandwidth and memory for input/output buffers.
 *
 * The execution time to reach to be logged in the slow log is set
 * using the 'commandlog-execution-slower-than' config directive, that is also
 * readable and writable using the CONFIG SET/GET command.
 *
 * Other configurations such as `commandlog-request-larger-than` and
 * `commandlog-reply-larger-than` can be found with more detailed
 * explanations in the config file.
 *
 * The command log is actually not "logged" in the server log file
 * but is accessible thanks to the COMMANDLOG command.
 *
 * ----------------------------------------------------------------------------
 */

#include "commandlog.h"
#include "script.h"

/* Create a new commandlog entry.
 * Incrementing the ref count of all the objects retained is up to
 * this function. */
static commandlogEntry *commandlogCreateEntry(client *c, robj **argv, int argc, long long value, int type) {
    commandlogEntry *ce = zmalloc(sizeof(*ce));
    int j, ceargc = argc;

    if (ceargc > COMMANDLOG_ENTRY_MAX_ARGC) ceargc = COMMANDLOG_ENTRY_MAX_ARGC;
    ce->argc = ceargc;
    ce->argv = zmalloc(sizeof(robj *) * ceargc);
    for (j = 0; j < ceargc; j++) {
        /* Logging too many arguments is a useless memory waste, so we stop
         * at COMMANDLOG_ENTRY_MAX_ARGC, but use the last argument to specify
         * how many remaining arguments there were in the original command. */
        if (ceargc != argc && j == ceargc - 1) {
            ce->argv[j] =
                createObject(OBJ_STRING, sdscatprintf(sdsempty(), "... (%d more arguments)", argc - ceargc + 1));
        } else {
            /* Trim too long strings as well... */
            if (argv[j]->type == OBJ_STRING && sdsEncodedObject(argv[j]) &&
                sdslen(objectGetVal(argv[j])) > COMMANDLOG_ENTRY_MAX_STRING) {
                sds s = sdsnewlen(objectGetVal(argv[j]), COMMANDLOG_ENTRY_MAX_STRING);

                s = sdscatprintf(s, "... (%lu more bytes)",
                                 (unsigned long)sdslen(objectGetVal(argv[j])) - COMMANDLOG_ENTRY_MAX_STRING);
                ce->argv[j] = createObject(OBJ_STRING, s);
            } else if (argv[j]->refcount == OBJ_SHARED_REFCOUNT) {
                ce->argv[j] = argv[j];
            } else {
                /* Here we need to duplicate the string objects composing the
                 * argument vector of the command, because those may otherwise
                 * end shared with string objects stored into keys. Having
                 * shared objects between any part of the server, and the data
                 * structure holding the data, is a problem: FLUSHALL ASYNC
                 * may release the shared string object and create a race. */
                ce->argv[j] = dupStringObject(argv[j]);
            }
        }
    }
    ce->time = time(NULL);
    ce->value = value;
    ce->id = server.commandlog[type].entry_id++;
    ce->peerid = sdsnew(getClientPeerId(c));
    ce->cname = c->name ? sdsnew(objectGetVal(c->name)) : sdsempty();

    /* Copy module-set commandlog metadata from client if present. */
    if (c->commandlog_metadata && dictSize(c->commandlog_metadata) > 0) {
        ce->metadata = dictCreate(&sdsSdsDictType);
        dictIterator *di = dictGetIterator(c->commandlog_metadata);
        dictEntry *de;
        while ((de = dictNext(di)) != NULL) {
            sds key = sdsdup(dictGetKey(de));
            sds val = sdsdup(dictGetVal(de));
            dictAdd(ce->metadata, key, val);
        }
        dictReleaseIterator(di);
    } else {
        ce->metadata = NULL;
    }

    /* Copy sub-path latencies from client (meaningful for slow command log). */
    ce->subpath_qb_wait = c->subpath_qb_wait;
    ce->subpath_blocked_wait = c->subpath_blocked_wait;
    ce->subpath_processing = c->subpath_processing;
    ce->subpath_ob_wait = 0; /* Will be updated when output buffer is written to socket. */
    return ce;
}

/* Free a command log entry. The argument is void so that the prototype of this
 * function matches the one of the 'free' method of adlist.c.
 *
 * This function will take care to release all the retained object. */
static void commandlogFreeEntry(void *ceptr) {
    commandlogEntry *ce = ceptr;
    int j;

    for (j = 0; j < ce->argc; j++) decrRefCount(ce->argv[j]);
    zfree(ce->argv);
    sdsfree(ce->peerid);
    sdsfree(ce->cname);
    if (ce->metadata) dictRelease(ce->metadata);
    zfree(ce);
}

/* Initialize the command log. This function should be called a single time
 * at server startup. */
void commandlogInit(void) {
    for (int i = 0; i < COMMANDLOG_TYPE_NUM; i++) {
        server.commandlog[i].entries = listCreate();
        server.commandlog[i].entry_id = 0;
        listSetFreeMethod(server.commandlog[i].entries, commandlogFreeEntry);
    }
}

/* Push a new entry into the command log.
 * This function will make sure to trim the command log accordingly to the
 * configured max length. */
static void commandlogPushEntryIfNeeded(client *c, robj **argv, int argc, long long value, int type) {
    if (server.commandlog[type].threshold < 0 || server.commandlog[type].max_len == 0) return; /* The corresponding commandlog disabled */
    if (value >= server.commandlog[type].threshold)
        listAddNodeHead(server.commandlog[type].entries, commandlogCreateEntry(c, argv, argc, value, type));

    /* Remove old entries if needed. */
    while (listLength(server.commandlog[type].entries) > server.commandlog[type].max_len) listDelNode(server.commandlog[type].entries, listLast(server.commandlog[type].entries));
}

/* Remove all the entries from the current command log of the specified type. */
static void commandlogReset(int type) {
    while (listLength(server.commandlog[type].entries) > 0) listDelNode(server.commandlog[type].entries, listLast(server.commandlog[type].entries));
}

/* Reply command logs to client. */
static void commandlogGetReply(client *c, int type, long count) {
    listIter li;
    listNode *ln;
    commandlogEntry *ce;

    if (count > (long)listLength(server.commandlog[type].entries)) {
        count = listLength(server.commandlog[type].entries);
    }
    addReplyArrayLen(c, count);
    listRewind(server.commandlog[type].entries, &li);
    while (count--) {
        int j;
        int has_subpath = (type == COMMANDLOG_TYPE_SLOW);

        ln = listNext(&li);
        ce = ln->value;

        /* Compute the number of fields in the entry reply.
         * Base fields: id, timestamp, value, argv, peerid, cname = 6
         * +1 if metadata is present
         * +1 if sub-path latencies are present (slow type only) */
        int nfields = 6;
        if (ce->metadata) nfields++;
        if (has_subpath) nfields++;

        addReplyArrayLen(c, nfields);
        addReplyLongLong(c, ce->id);
        addReplyLongLong(c, ce->time);
        addReplyLongLong(c, ce->value);
        addReplyArrayLen(c, ce->argc);
        for (j = 0; j < ce->argc; j++) addReplyBulk(c, ce->argv[j]);
        addReplyBulkCBuffer(c, ce->peerid, sdslen(ce->peerid));
        addReplyBulkCBuffer(c, ce->cname, sdslen(ce->cname));
        if (ce->metadata) {
            unsigned long mfields = dictSize(ce->metadata);
            addReplyArrayLen(c, mfields * 2);
            dictIterator *di = dictGetIterator(ce->metadata);
            dictEntry *de;
            while ((de = dictNext(di)) != NULL) {
                sds key = dictGetKey(de);
                sds val = dictGetVal(de);
                addReplyBulkCBuffer(c, key, sdslen(key));
                addReplyBulkCBuffer(c, val, sdslen(val));
            }
            dictReleaseIterator(di);
        }
        if (has_subpath) {
            /* Sub-path latency breakdown as a map of 4 key-value pairs (all in microseconds):
             * input-buffer-wait: time waiting in query buffer before parsing
             * blocked-wait: time spent blocked/throttled before execution
             * processing: time spent executing the command
             * output-buffer-wait: time waiting in output buffer before write to socket */
            addReplyArrayLen(c, 8);
            addReplyBulkCString(c, "input-buffer-wait");
            addReplyLongLong(c, ce->subpath_qb_wait);
            addReplyBulkCString(c, "blocked-wait");
            addReplyLongLong(c, ce->subpath_blocked_wait);
            addReplyBulkCString(c, "processing");
            addReplyLongLong(c, ce->subpath_processing);
            addReplyBulkCString(c, "output-buffer-wait");
            addReplyLongLong(c, ce->subpath_ob_wait);
        }
    }
}

/* Log the last command a client executed into the commandlog. */
void commandlogPushCurrentCommand(client *c, struct serverCommand *cmd) {
    /* Some commands may contain sensitive data that should not be available in the commandlog.
     */
    if (cmd->flags & CMD_SKIP_COMMANDLOG) return;

    /* If command argument vector was rewritten, use the original
     * arguments. */
    robj **argv = c->original_argv ? c->original_argv : c->argv;
    int argc = c->original_argv ? c->original_argc : c->argc;

    /* In script, client will be replaced with its caller, so commandlog needs to use the metrics
     * of the client that currently executing the command. */
    long duration = c->duration;
    unsigned long long net_input_bytes_curr_cmd = c->net_input_bytes_curr_cmd;
    unsigned long long net_output_bytes_curr_cmd = c->net_output_bytes_curr_cmd;

    /* If a script is currently running, the client passed in is a
     * fake client. Or the client passed in is the original client
     * if this is a EVAL or alike, doesn't matter. In this case,
     * use the original client to get the client information. */
    c = scriptIsRunning() ? scriptGetCaller() : c;

    commandlogPushEntryIfNeeded(c, argv, argc, duration, COMMANDLOG_TYPE_SLOW);
    commandlogPushEntryIfNeeded(c, argv, argc, net_input_bytes_curr_cmd, COMMANDLOG_TYPE_LARGE_REQUEST);
    commandlogPushEntryIfNeeded(c, argv, argc, net_output_bytes_curr_cmd, COMMANDLOG_TYPE_LARGE_REPLY);
}

/* The SLOWLOG command. Implements all the subcommands needed to handle the
 * slow log. */
void slowlogCommand(client *c) {
    if (c->argc == 2 && !strcasecmp(objectGetVal(c->argv[1]), "help")) {
        const char *help[] = {
            "GET [<count>]",
            "    Return top <count> entries from the slowlog (default: 10, -1 mean all).",
            "    Entries are made of:",
            "    id, timestamp, time in microseconds, arguments array, client IP and port,",
            "    client name, sub-path latencies (input-buffer-wait, blocked-wait, processing, output-buffer-wait)",
            "LEN",
            "    Return the length of the slowlog.",
            "RESET",
            "    Reset the slowlog.",
            NULL,
        };
        addReplyHelp(c, help);
    } else if (c->argc == 2 && !strcasecmp(objectGetVal(c->argv[1]), "reset")) {
        commandlogReset(COMMANDLOG_TYPE_SLOW);
        addReply(c, shared.ok);
    } else if (c->argc == 2 && !strcasecmp(objectGetVal(c->argv[1]), "len")) {
        addReplyLongLong(c, listLength(server.commandlog[COMMANDLOG_TYPE_SLOW].entries));
    } else if ((c->argc == 2 || c->argc == 3) && !strcasecmp(objectGetVal(c->argv[1]), "get")) {
        long count = 10;

        if (c->argc == 3) {
            /* Consume count arg. */
            if (getRangeLongFromObjectOrReply(c, c->argv[2], -1, LONG_MAX, &count,
                                              "count should be greater than or equal to -1") != C_OK)
                return;

            if (count == -1) {
                /* We treat -1 as a special value, which means to get all slow logs.
                 * Simply set count to the length of server.commandlog. */
                count = listLength(server.commandlog[COMMANDLOG_TYPE_SLOW].entries);
            }
        }

        commandlogGetReply(c, COMMANDLOG_TYPE_SLOW, count);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}

static int commandlogGetTypeOrReply(client *c, robj *o) {
    if (!strcasecmp(objectGetVal(o), "slow")) return COMMANDLOG_TYPE_SLOW;
    if (!strcasecmp(objectGetVal(o), "large-request")) return COMMANDLOG_TYPE_LARGE_REQUEST;
    if (!strcasecmp(objectGetVal(o), "large-reply")) return COMMANDLOG_TYPE_LARGE_REPLY;
    addReplyError(c, "type should be one of the following: slow, large-request, large-reply");
    return -1;
}

/* The COMMANDLOG command. Implements all the subcommands needed to handle the
 * command log. */
void commandlogCommand(client *c) {
    int type;
    if (c->argc == 2 && !strcasecmp(objectGetVal(c->argv[1]), "help")) {
        const char *help[] = {
            "GET <count> <type>",
            "    Return top <count> entries of the specified <type> from the commandlog (-1 mean all).",
            "    Entries are made of:",
            "    id, timestamp,",
            "        time in microseconds for type of slow,",
            "        or size in bytes for type of large-request,",
            "        or size in bytes for type of large-reply",
            "    arguments array, client IP and port,",
            "    client name,",
            "    sub-path latencies (input-buffer-wait, blocked-wait, processing, output-buffer-wait) for slow type",
            "LEN <type>",
            "    Return the length of the specified type of commandlog.",
            "RESET <type>",
            "    Reset the specified type of commandlog.",
            NULL,
        };
        addReplyHelp(c, help);
    } else if (c->argc == 3 && !strcasecmp(objectGetVal(c->argv[1]), "reset")) {
        if ((type = commandlogGetTypeOrReply(c, c->argv[2])) == -1) return;
        commandlogReset(type);
        addReply(c, shared.ok);
    } else if (c->argc == 3 && !strcasecmp(objectGetVal(c->argv[1]), "len")) {
        if ((type = commandlogGetTypeOrReply(c, c->argv[2])) == -1) return;
        addReplyLongLong(c, listLength(server.commandlog[type].entries));
    } else if (c->argc == 4 && !strcasecmp(objectGetVal(c->argv[1]), "get")) {
        long count;

        /* Consume count arg. */
        if (getRangeLongFromObjectOrReply(c, c->argv[2], -1, LONG_MAX, &count,
                                          "count should be greater than or equal to -1") != C_OK)
            return;

        if ((type = commandlogGetTypeOrReply(c, c->argv[3])) == -1) return;

        if (count == -1) {
            /* We treat -1 as a special value, which means to get all command logs.
             * Simply set count to the length of server.commandlog. */
            count = listLength(server.commandlog[type].entries);
        }

        commandlogGetReply(c, type, count);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}
