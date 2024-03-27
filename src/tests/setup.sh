##  Copyright 2021-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  ------------------------------------------------------------------------
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  Super Mediator 2.0.0
##
##  Copyright 2023 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##  Contract No.: FA8702-15-D-0002
##  Contractor Name: Carnegie Mellon University
##  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
##  The Government's rights to use, modify, reproduce, release, perform,
##  display, or disclose this software are restricted by paragraph (b)(2) of
##  the Rights in Noncommercial Computer Software and Noncommercial Computer
##  Software Documentation clause contained in the above identified
##  contract. No restrictions apply after the expiration date shown
##  above. Any reproduction of the software or portions thereof marked with
##  this legend must also reproduce the markings.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM23-2321
##  @DISTRIBUTION_STATEMENT_END@
##  ------------------------------------------------------------------------

#  File to be sourced by the test scripts in this directory.
#

#  set super_mediator if not set
super_mediator="${super_mediator-./super_mediator}"

#  get the tempdir
tempdir="${TMPDIR-/tmp}"
if [ ! -d "${tempdir}" ]; then
    echo "1..0 # Skip: tempdir '${tempdir}' is not a directory"
    exit
fi

# Runs super_mediator and expects the command to succeed.
#
# The first argument is the test number. Remaining arguments are used
# to invoke super_mediator.
run_sm_ok() {
    testnum=$1
    shift
    echo '#' '${super_mediator}' "$@"
    ${super_mediator} "$@"
    ret=$?
    if [ $ret -eq 0 ] ; then
        echo "ok $testnum"
    else
        echo "not ok $testnum"
    fi
    return $ret
}

# Runs super_mediator and expects the command to fail.
#
# The first argument is the test number. Remaining arguments are used
# to invoke super_mediator.
run_sm_xfail() {
    testnum=$1
    shift
    echo '#' '${super_mediator}' "$@"
    ${super_mediator} "$@"
    ret=$?
    if [ $ret -ne 0 ] ; then
        echo "ok $testnum"
        ret=0
    else
        echo "not ok $testnum"
        ret=1
    fi
    return $ret
}

# Runs super_mediator and expects the command to fail and prints a
# TODO message when it does
#
# The first argument is the test number.  The second argument is the
# reason why this is a TODO.  Remaining arguments are used to invoke
# super_mediator.
run_sm_todo() {
    testnum=$1
    shift
    todo_reason=$1
    shift
    echo '#' '${super_mediator}' "$@"
    ${super_mediator} "$@"
    ret=$?
    if [ $ret -eq 0 ] ; then
        echo "ok $testnum - Issue resolved: TODO ${todo_reason}"
    else
        echo "not ok $testnum # TODO ${todo_reason}"
    fi
    return $ret
}

# Run super_mediator with the --version flag and bail out if it fails
# to run.
check_sm_version() {
    ${super_mediator} --version
    if [ $? -ne 0 ]; then
        echo "Bail out! Unable to run ${super_mediator} --version"
    fi
}

# Makes a temporary file
#
# If first arg is "--no-error", this function returns 1 on error
# instead of echoing "Bail out!"
#
# The argument (or second argument if first is --no-error) is used as
# part of the temporary file's name.
#
make_temp() {
    make_temp_no_error=0
    if [ "x${1}" = "x--no-error" ] ; then
        make_temp_no_error=1
        shift
    fi
    template="${tempdir}"/sm-test-"${1}"-XXXXXXXX
    file=`mktemp "${template}"`
    if [ $? != 0 ] ; then
        if [ ${make_temp_no_error} -eq 1 ] ; then
            return 1
        fi
        echo "Bail out! mktemp failed to create file from '${template}' \$?=$?"
    fi
    if [ ! -f "${file}" ]; then
        if [ ${make_temp_no_error} -eq 1 ] ; then
            return 1
        fi
        echo "Bail out! result of mktemp is not a file '${file}'"
    fi
    echo "${file}"
    return 0
}

# Makes a temporary directory
#
# If first arg is "--no-error", this function returns 1 on error
# instead of echoing "Bail out!"
#
# The argument (or second argument if first is --no-error) is used as
# part of the temporary directory's name.
#
make_tempdir() {
    make_tempdir_no_error=0
    if [ "x${1}" = "x--no-error" ] ; then
        make_tempdir_no_error=1
        shift
    fi
    template="${tempdir}"/sm-testdir-"${1}"-XXXXXXXX
    dir=`mktemp -d "${template}"`
    if [ $? != 0 ] ; then
        if [ ${make_tempdir_no_error} -eq 1 ] ; then
            return 1
        fi
        echo "Bail out! mktemp failed to create dir from '${template}' \$?=$?"
    fi
    if [ ! -d "${dir}" ]; then
        if [ ${make_tempdir_no_error} -eq 1 ] ; then
            return 1
        fi
        echo "Bail out! result of mktemp -d is not a directory '${dir}'"
    fi
    echo "${dir}"
    return 0
}


# Check whether "mktemp" works.  Skip all tests if it does not
check_make_temp() {
    check_make_temp_file=`make_temp --no-error ${testnum}`
    if [ $? != 0 -o -z "${check_make_temp_file}" ]; then
        echo "1..0 # Skip: Problem making temporary file with mktemp"
        exit
    fi
    rm -f "${check_make_temp_file}"
    return 0
}

# Check whether "mktemp" works.  Skip all tests if it does not
check_make_tempdir() {
    #  create a temporary directory
    check_make_tempdir_dir=`make_tempdir ${testnum}`
    if [ $? != 0 -o -z "${check_make_tempdir_dir}" ]; then
        echo "1..0 # Skip: Problem making temporary directory with mktemp"
        exit
    fi
    rmdir "${check_make_tempdir_dir}"
    return 0
}

# Check whether the argument(s) are files and skip all tests if not
#
# This is intended to be used to skip all tests in a file if some file
# is missing, such an IPFIX file to use an input to super_mediator
check_files_exist() {
    for i in "$@" /dev/null ; do
        if [ -n "${i}" -a ! -f "${i}" -a "x${i}" != "x/dev/null" ] ; then
            echo "1..0 # Skip: Missing required file '${i}'"
            exit
        fi
    done
}

# Removes the argument(s) (via "rm -f") if the last command completed
# successfully
remove_if_success() {
    if [ $? -eq 0 ] ; then
        rm -f "$@"
    fi
}
