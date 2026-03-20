"""Fixture: contains subprocess shell injection patterns."""

import os
import subprocess


def run_user_command(user_input):
    os.system(user_input)


def run_with_popen(cmd):
    proc = subprocess.Popen(cmd, shell=True)
    return proc.communicate()


def run_with_call(cmd):
    subprocess.call(cmd, shell=True)
