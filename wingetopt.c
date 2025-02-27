/*
 * Windows compatible getopt implementation 
 * Based on public domain code with modifications for Harkonnen
 */

#include <stdio.h>
#include <string.h>
#include "wingetopt.h"

char *optarg;
int optind = 1;
int opterr = 1;
int optopt;

static int getopt_internal(int argc, char *const argv[], const char *optstring,
                           const struct option *longopts, int *longindex, int long_only);

int getopt(int argc, char *const argv[], const char *optstring) {
    return getopt_internal(argc, argv, optstring, NULL, NULL, 0);
}

int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    return getopt_internal(argc, argv, optstring, longopts, longindex, 0);
}

static int getopt_internal(int argc, char *const argv[], const char *optstring,
                           const struct option *longopts, int *longindex, int long_only) {
    static char *nextchar;
    static int optpos = 0;
    char *cp;
    int c;

    if (optind == 0) {
        optind = 1;
        optpos = 0;
    }

    if (optpos == 0) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        } else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }

    if (longopts != NULL && 
        (argv[optind][1] == '-' || (long_only && (argv[optind][0] == '-' && argv[optind][1] != '\0')))) {
        char *arg = argv[optind] + 1 + (argv[optind][1] == '-');
        const struct option *o;
        const struct option *long_match = NULL;
        int match_index = -1;
        int exact_match = 0;
        int ambiguous = 0;

        for (o = longopts, match_index = 0; o->name != NULL; o++, match_index++) {
            if (strncmp(o->name, arg, strlen(o->name)) == 0) {
                if (strlen(o->name) == strlen(arg)) {
                    exact_match = 1;
                    long_match = o;
                    break;
                } else if (long_match == NULL) {
                    long_match = o;
                } else {
                    ambiguous = 1;
                }
            }
        }

        if (ambiguous && !exact_match) {
            optind++;
            optopt = 0;
            return '?';
        }

        if (long_match != NULL) {
            optind++;
            if (long_match->has_arg != no_argument) {
                if (optind < argc) {
                    optarg = argv[optind++];
                } else if (long_match->has_arg == required_argument) {
                    if (opterr) {
                        fprintf(stderr, "%s: option requires an argument -- %s\n", 
                                argv[0], long_match->name);
                    }
                    optopt = long_match->val;
                    return '?';
                }
            }
            if (longindex != NULL) {
                *longindex = match_index;
            }
            if (long_match->flag != NULL) {
                *long_match->flag = long_match->val;
                return 0;
            }
            return long_match->val;
        } else {
            if (opterr) {
                fprintf(stderr, "%s: illegal option -- %s\n", argv[0], arg);
            }
            optind++;
            optopt = 0;
            return '?';
        }
    }

    c = argv[optind][++optpos];
    cp = strchr(optstring, c);

    if (cp == NULL || c == ':') {
        if (argv[optind][optpos+1] == '\0') {
            optind++;
            optpos = 0;
        }
        if (opterr) {
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        }
        optopt = c;
        return '?';
    }

    if (cp[1] == ':') {
        if (argv[optind][optpos+1] != '\0') {
            optarg = &argv[optind][optpos+1];
            optind++;
            optpos = 0;
        } else if (++optind < argc) {
            optarg = argv[optind++];
            optpos = 0;
        } else {
            if (opterr) {
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            }
            optopt = c;
            return cp[2] == ':' ? ':' : '?';
        }
    } else {
        if (argv[optind][optpos+1] == '\0') {
            optind++;
            optpos = 0;
        }
        optarg = NULL;
    }

    return c;
}