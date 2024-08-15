#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Jan-Piet Mens <jp@mens.de>

__metaclass__ = type

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import missing_required_lib
import secrets
import os

LIB_IMP_ERR = None
try:
    from pykeepass import PyKeePass, create_database

    HAS_LIB = True
except Exception:
    HAS_LIB = False
    LIB_IMP_ERR = traceback.format_exc()


DOCUMENTATION = r"""
---
module: keepassxc_add_entry
author:
  - Jan-Piet Mens (@jpmens)

short_description: Add/delete a KeePassXC password entry
description:
  - This module adds an entry to a KeePassXC database file, optionally creating
    the database which can be protected with a key file and a password. Entries
    can also be deleted by title and user.

version_added: "0.1.0"

requirements:
  - pykeepass

options:
  database:
    description: >-
       Path to KeePassXC database file; must exist unless C(create=True)
       in which case the database is created. If either of C(password)
       and/or C(keyfile) are specified during creation, these parameters
       will always have to be specified on future opens.
    required: true
    type: str
    aliases: path
  create:
    description: If C(true), creates the database on open should it not exist
    required: false
    type: bool
    default: false
  keyfile:
    description: >-
        Optional key file used for accessing KeePassXC database file. This file
        contains random data with which encryption of the database file is
        augmented. Create the file with, say C(openssl rand -out keyfile 128)
    required: false
    type: str
  password:
    description: >
      Password for KeePassXC database file. One or both of I(password) or I(keyfile) 
      must be used.
    required: False
    type: str
  entrypath:
    description: Entry path under which to add entries; is created if non-existent
    required: false
    type: str
    default: root-group
  title:
    description: Title (name) of entry
    required: true
    type: str
  secret:
    description: >
      Password for entry. A random C(secrets.token_urlsafe(32)) value is
      used if none is specified here.
    required: false
    type: str
    default: random secret
  tags:
    description: List of tags to be associated with the entry
    required: false
    type: list
  url:
    description: A URL to be associated with the entry
    required: false
    type: text
  notes:
    description: Notes to be associated with the entry
    required: false
    type: text
  state:
    description: Whether the new entry should be present or absent
    type: text
    default: present
    choices: [ present, absent ]
  force:
    description: >
         Whether to force overwriting entry in database. Setting this to the
         true can cause the database to have duplicate entries added
    type: bool
    default: false

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  platform:
    platforms: posix
"""

EXAMPLES = r"""
- name: Open KDBX and create a new entry for www01
  keepassxc_add_entry:
    database: file.kdbx
    create: true
    password: "secret"
    entrypath: "/Frankfurt/South/Webservers"
    title: "www{{ 40|random }}"
    user: "ansible"
    # secret: "bla"
    tags: [ ansible, olympia ]
    url: http://example.net
    notes: >
       Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
       eiusmod tempor incididunt ut labore et dolore magna aliqua.
"""

RETURN = r""" # """


def main():
    module_args = dict(
        database = dict(type="str", required=True, aliases=["path"]),
        create = dict(type="bool", required=False, default=False),
        keyfile = dict(type="str", no_log=True, required=False),
        password = dict(type="str", no_log=True, required=False),
        entrypath = dict(type="str", required=False),
        title = dict(type="str", required=True),
        user = dict(type="str", required=True),
        secret = dict(type="str", no_log=True, required=False),
        tags = dict(type="list", required=False),
        url = dict(type="str", required=False),
        notes = dict(type="str", required=False),
        state = dict(type="str", choices=[ "present", "absent" ], default="present"),
        force = dict(type="bool", required=False, default=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of = [["keyfile", "password"]],
    )

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("pykeepass"), exception=LIB_IMP_ERR)

    result = {}
    changed = False

    database = module.params["database"]
    create = module.params["create"]
    keyfile = module.params["keyfile"]
    password = module.params["password"]
    entrypath = module.params["entrypath"]
    title = module.params["title"]
    user = module.params["user"]
    secret = module.params["secret"]
    tags = module.params["tags"]
    url = module.params["url"]
    notes = module.params["notes"]
    state = module.params["state"]
    force = module.params["force"]
    
    if os.path.isdir(database):
        module.fail_json(rc=256, msg="Destination {0} is a directory!".format(database))

    kdb = None
    try:
        kdb = PyKeePass(database, password=password, keyfile=keyfile)
    except FileNotFoundError:
        if create:
            try:
                kdb = create_database(database, password=password, keyfile=keyfile, transformed_key=None)
            except Exception as e:
                module.fail_json( msg="Cannot create {0}: {1}".format(database, str(e)))
        else:
            module.fail_json(msg="Cannot open database {0}".format(database))
    except Exception as e:
        module.fail_json( msg="Cannot open database {0}: {1}".format(database, str(e)))
                

    if entrypath is None:
        group = kdb.root_group
    else:
        group = kdb.find_groups(name=entrypath, first=True)
        if group is None:
            group = kdb.add_group(kdb.root_group, entrypath)

    result["database"] = database
    if entrypath:
        result["entrypath"] = entrypath
    result["title"] = title
    result["user"] = user
    if tags:
        result["tags"] = tags
    
    if secret is None:
        secret = secrets.token_urlsafe(32)

    if state == "present":
        try:
            entry = kdb.add_entry(group, title, user, secret, tags=tags, url=url, notes=notes, force_creation=force)
            changed = True
        except Exception as e:
            module.fail_json( msg="Cannot add entry {0} to database {1}: {2}".format(title, database, str(e)))
    else:
        entry = kdb.find_entries(title=title, username=user, first=True)
        if entry is None:
            module.fail_json(msg="Can't find title {0} / user {1}".format(title, user))
        else:
            try:
                kdb.delete_entry(entry)
                changed = True
            except Exception as e:
                module.fail_json( msg="Cannot delete entry {0}: {1}".format(title, str(e)))


    kdb.save()

    result["changed"] = changed
    module.exit_json(**result)


if __name__ == "__main__":
    main()
