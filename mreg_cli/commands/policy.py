"""Policy commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Atom, Host, HostPolicy, Role
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, get_list, patch, post
from mreg_cli.utilities.history import format_history_items, get_history_items
from mreg_cli.utilities.host import host_info_by_name

command_registry = CommandRegistry()


class PolicyCommands(BaseCommand):
    """Policy commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the policy commands."""
        super().__init__(
            cli, command_registry, "policy", "Manage policies for hosts.", "Manage policies"
        )


def _get_atom(name: str) -> list[dict[str, Any]]:
    """Return a list with the atom info."""
    return get_list("/api/v1/hostpolicy/atoms/", params={"name": name})


def get_atom(name: str) -> dict[str, Any]:
    """Return the atom info."""
    ret = _get_atom(name)
    if not ret:
        cli_warning(f"Atom {name!r} does not exist")
    return ret[0]


def _get_role(name: str) -> list[dict[str, Any]]:
    """Return a list with the role info."""
    return get_list("/api/v1/hostpolicy/roles/", params={"name": name})


def get_role(name: str) -> dict[str, Any]:
    """Return the role info."""
    ret = _get_role(name)
    if not ret:
        cli_warning(f"Role {name!r} does not exist")
    return ret[0]


def get_atom_or_role(name: str) -> tuple[str, dict[str, Any]]:
    """Return the atom or role info."""
    atom = _get_atom(name)
    if atom:
        return "atom", atom[0]
    role = _get_role(name)
    if role:
        return "role", role[0]
    cli_warning(f"Could not find an atom or a role with name: {name!r}")


@command_registry.register_command(
    prog="atom_create",
    description="Create a new atom",
    short_desc="Create a new atom",
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)
def atom_create(args: argparse.Namespace) -> None:
    """Create a new atom.

    :param args: argparse.Namespace (name, description, created)
    """
    Atom.ensure_name_not_exists(args.name)

    params = {"name": args.name, "description": args.description}
    if args.created:
        params["create_date"] = args.created

    Atom.create(params)
    cli_info(f"Created new atom {args.name}", print_msg=True)


@command_registry.register_command(
    prog="atom_delete",
    description="Delete an atom",
    short_desc="Delete an atom",
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
    ],
)
def atom_delete(args: argparse.Namespace) -> None:
    """Delete an atom.

    :param args: argparse.Namespace (name)
    """
    atom = Atom.get_by_name_or_raise(args.name)

    roles = Role.get_roles_with_atom(args.name)
    if roles:
        inuse = ", ".join([role.name for role in roles])
        cli_error(f"Atom {args.name} used in roles: {inuse}")

    if atom.delete():
        cli_info(f"Deleted atom {args.name}", print_msg=True)
    else:
        cli_error(f"Failed to delete atom {args.name}")


@command_registry.register_command(
    prog="role_create",
    description="Create a new role",
    short_desc="Create a new role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)
def role_create(args: argparse.Namespace) -> None:
    """Create a new role.

    :param args: argparse.Namespace (name, description, created)
    """
    Role.ensure_name_not_exists(args.name)

    params = {"name": args.name, "description": args.description}
    if args.created:
        params["create_date"] = args.created

    Role.create(params)
    cli_info(f"Created new role {args.name!r}", print_msg=True)


@command_registry.register_command(
    prog="role_delete",
    description="Delete a role",
    short_desc="Delete a role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)
def role_delete(args: argparse.Namespace) -> None:
    """Delete a role.

    :param args: argparse.Namespace (name)
    """
    role = Role.get_by_name_or_raise(args.name)
    if role.hosts:
        hosts = ", ".join(role.hosts)
        cli_error(f"Role {args.name!r} used on hosts: {hosts}")
    if role.delete():
        cli_info(f"Deleted role {args.name!r}", print_msg=True)
    else:
        cli_error(f"Failed to delete role {args.name!r}")


@command_registry.register_command(
    prog="add_atom",
    description="Make an atom member of a role",
    short_desc="Make an atom member of a role",
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)
def add_atom(args: argparse.Namespace) -> None:
    """Make an atom member of a role.

    :param args: argparse.Namespace (role, atom)
    """
    role = Role.get_by_name_or_raise(args.role)
    for atom in role.atoms:
        if args.atom == atom:
            cli_info(
                f"Atom {args.atom!r} already a member of role {args.role!r}",
                print_msg=True,
            )
            return

    Atom.ensure_name_exists(args.atom)

    if role.add_atom(args.atom):
        cli_info(f"Added atom {args.atom!r} to role {args.role!r}", print_msg=True)
    else:
        cli_error(f"Failed to add atom {args.atom!r} to role {args.role!r}")


@command_registry.register_command(
    prog="remove_atom",
    description="Remove an atom member from a role",
    short_desc="Remove an atom member from a role",
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)
def remove_atom(args: argparse.Namespace) -> None:
    """Remove an atom member from a role.

    :param args: argparse.Namespace (role, atom)
    """
    role = Role.get_by_name_or_raise(args.role)
    for atom in role.atoms:
        if args.atom == atom:
            break
    else:
        cli_warning(f"Atom {args.atom!r} not a member of {args.role!r}")

    if role.remove_atom(args.atom):
        cli_info(f"Removed atom {args.atom!r} from role {args.role!r}", print_msg=True)
    else:
        cli_error(f"Failed to remove atom {args.atom!r} from role {args.role!r}")


@command_registry.register_command(
    prog="info",
    description="Show info about an atom or role",
    short_desc="atom/role info",
    flags=[
        Flag("name", description="atom/role name", nargs="+", metavar="NAME"),
    ],
)
def info(args: argparse.Namespace) -> None:
    """Show info about an atom or role.

    :param args: argparse.Namespace (name)
    """
    names: list[str] = args.name
    for name in names:
        role_or_atom = HostPolicy.get_role_or_atom_or_raise(name)
        role_or_atom.output()


@command_registry.register_command(
    prog="list_atoms",
    description="List all atoms by given filters",
    short_desc="List all atoms by given filters",
    flags=[
        Flag(
            "name",
            description="Atom name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)
def list_atoms(args: argparse.Namespace) -> None:
    """List all atoms by given filters.

    :param args: argparse.Namespace (name)
    """
    atoms = Atom.get_list_by_name_regex(args.name)
    if atoms:
        Atom.output_multiple_lines(atoms)
    else:
        OutputManager().add_line("No match")


@command_registry.register_command(
    prog="list_roles",
    description="List all roles by given filters",
    short_desc="List all roles by given filters",
    flags=[
        Flag(
            "name",
            description="Role name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)
def list_roles(args: argparse.Namespace) -> None:
    """List all roles by given filters.

    :param args: argparse.Namespace (name)
    """
    roles = Role.get_list_by_name_regex(args.name)
    if not roles:
        OutputManager().add_line("No match")
        return
    Role.output_multiple_table(roles)


@command_registry.register_command(
    prog="list_hosts",
    description="List hosts which use the given role",
    short_desc="List hosts which use the given role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)
def list_hosts(args: argparse.Namespace) -> None:
    """List hosts which use the given role.

    :param args: argparse.Namespace (name)
    """
    role = Role.get_by_name_or_raise(args.name)
    role.output_hosts()


@command_registry.register_command(
    prog="list_members",
    description="List all members of a role",
    short_desc="List role members",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)
def list_members(args: argparse.Namespace) -> None:
    """List atom members for a role.

    :param args: argparse.Namespace (name)
    """
    role = Role.get_by_name_or_raise(args.name)
    role.output_atoms()


@command_registry.register_command(
    prog="host_add",
    description="Add host(s) to role",
    short_desc="Add host(s) to role",
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)
def host_add(args: argparse.Namespace) -> None:
    """Add host(s) to role.

    :param args: argparse.Namespace (role, hosts)
    """
    role = Role.get_by_name_or_raise(args.role)
    hosts = [Host.get_by_any_means_or_raise(host) for host in args.hosts]

    for host in hosts:
        role.add_host(host.name.hostname)
        cli_info(f"Added host {host.name!r} to role {args.role!r}", print_msg=True)


@command_registry.register_command(
    prog="host_list",
    description="List roles for host(s)",
    short_desc="List roles for host(s)",
    flags=[
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)
def host_list(args: argparse.Namespace) -> None:
    """List host roles.

    :param args: argparse.Namespace (hosts)
    """
    for name in args.hosts:
        host = Host.get_by_any_means_or_raise(name)
        host.output_roles()


@command_registry.register_command(
    prog="host_remove",
    description="Remove host(s) from role",
    short_desc="Remove host(s) from role",
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="host", nargs="+", metavar="HOST"),
    ],
)
def host_remove(args: argparse.Namespace) -> None:
    """Remove host(s) from role.

    :param args: argparse.Namespace (role, hosts)
    """
    role = Role.get_by_name_or_raise(args.role)
    hosts = [Host.get_by_any_means_or_raise(host) for host in args.hosts]

    for host in hosts:
        role.remove_host(host.name.hostname)
        cli_info(f"Removed host {host.name!r} from role {args.role!r}", print_msg=True)


@command_registry.register_command(
    prog="rename",
    description="Rename an atom or role",
    short_desc="Rename an atom or role",
    flags=[
        Flag("oldname", description="Existing name", metavar="OLDNAME"),
        Flag("newname", description="New name", metavar="NEWNAME"),
    ],
)
def rename(args: argparse.Namespace) -> None:
    """Rename an atom/role.

    :param args: argparse.Namespace (oldname, newname)
    """
    if args.oldname == args.newname:
        cli_warning("Old and new names are the same")

    HostPolicy.ensure_name_not_exists(args.newname)

    role_or_atom = HostPolicy.get_role_or_atom_or_raise(args.oldname)
    role_or_atom.rename(args.newname)
    cli_info(f"Renamed {args.oldname!r} to {args.newname!r}", True)


@command_registry.register_command(
    prog="set_description",
    description="Set description for an atom or role",
    short_desc="Set description for an atom or role",
    flags=[
        Flag("name", description="Name", metavar="NAME"),
        Flag("description", description="Description.", metavar="DESC"),
    ],
)
def set_description(args: argparse.Namespace) -> None:
    """Set description for atom/role.

    :param args: argparse.Namespace (name, description)
    """
    role_or_atom = HostPolicy.get_role_or_atom_or_raise(args.name)
    role_or_atom.set_description(args.description)
    cli_info(f"updated description to {args.description!r} for {args.name!r}", print_msg=True)


@command_registry.register_command(
    prog="label_add",
    description="Add a label to a role",
    short_desc="Add label",
    flags=[
        Flag("label", description="Label name", metavar="LABEL"),
        Flag("role", description="Role name", metavar="ROLE"),
    ],
)
def add_label_to_role(args: argparse.Namespace) -> None:
    """Add a label to a role.

    :param args: argparse.Namespace (role, label)
    """
    role = Role.get_by_name_or_raise(args.role)
    role.add_label(args.label)
    cli_info(f"Added the label {args.label!r} to the role {args.role!r}.", print_msg=True)


@command_registry.register_command(
    prog="label_remove",
    description="Remove a label from a role",
    short_desc="Remove label",
    flags=[Flag("label"), Flag("role")],
)
def remove_label_from_role(args: argparse.Namespace) -> None:
    """Remove a label from a role.

    :param args: argparse.Namespace (role, label)
    """
    # find the role
    path = f"/api/v1/hostpolicy/roles/{args.role}"
    res = get(path, ok404=True)
    if not res:
        cli_warning(f"Could not find a role with name {args.role!r}")
    role = res.json()
    # find the label
    labelpath = f"/api/v1/labels/name/{args.label}"
    res = get(labelpath, ok404=True)
    if not res:
        cli_warning(f"Could not find a label with name {args.label!r}")
    label = res.json()
    # check if the role has the label
    if label["id"] not in role["labels"]:
        cli_warning(f"The role {args.role!r} doesn't have the label {args.label!r}")
    # patch the role
    ar = role["labels"]
    ar.remove(label["id"])
    patch(path, use_json=True, params={"labels": ar})
    cli_info(f"Removed the label {args.label!r} from the role {args.role!r}.", print_msg=True)


@command_registry.register_command(
    prog="atom_history",
    description="Show history for atom name",
    short_desc="Show history for atom name",
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)
def atom_history(args: argparse.Namespace) -> None:
    """Show history for name.

    :param args: argparse.Namespace (name)
    """
    items = get_history_items(args.name, "hostpolicy_atom", data_relation="atoms")
    format_history_items(args.name, items)


@command_registry.register_command(
    prog="role_history",
    description="Show history for role name",
    short_desc="Show history for role name",
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)
def role_history(args: argparse.Namespace) -> None:
    """Show history for name.

    :param args: argparse.Namespace (name)
    """
    items = get_history_items(args.name, "hostpolicy_role", data_relation="roles")
    format_history_items(args.name, items)
