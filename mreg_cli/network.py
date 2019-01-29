from util import *
from log import *
# noinspection PyUnresolvedReferences
from cli import cli, Flag
from history import history

###################################
#  Add the main command 'network'  #
###################################

network = cli.add_command(
    prog='network',
    description='Manage networks.',
)


##########################################
# Implementation of sub command 'create' #
##########################################

def create(args):
    """Create a new network
    """
    frozen = True if args.frozen else False
    if args.vlan:
        string_to_int(args.vlan, "VLAN")
    if args.category and not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")
    if args.location and not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    networks_existing = get("/networks/").json()
    for network in networks_existing:
        network_object = ipaddress.ip_network(network['range'])
        if network_object.overlaps(ipaddress.ip_network(args.network)):
            cli_warning("Overlap found between new network {} and existing "
                        "network {}".format(ipaddress.ip_network(args.network),
                                           network['range']))

    post("/networks/", range=args.network, description=args.desc, vlan=args.vlan,
         category=args.category, location=args.location, frozen=frozen)
    cli_info("created network {}".format(args.network), True)


network.add_command(
    prog='create',
    description='Create a new network',
    short_desc='Create a new network',
    callback=create,
    flags=[
        Flag('-network',
             description='Network.',
             required=True,
             metavar='NETWORK'),
        Flag('-desc',
             description='Network description.',
             required=True,
             metavar='DESCRIPTION'),
        Flag('-vlan',
             description='VLAN.',
             default=None,
             metavar='VLAN'),
        Flag('-category',
             description='Category.',
             default=None,
             metavar='Category'),
        Flag('-location',
             description='Location.',
             default=None,
             metavar='LOCATION'),
        Flag('-frozen',
             description='Set frozen network.',
             action='store_true'),
    ]
)


########################################
# Implementation of sub command 'info' #
########################################

def info(args):
    """Display network info
    """
    for ip_range in args.networks:
        # Get network info or raise exception
        network_info = get_network(ip_range)
        used = get_network_used_count(network_info['range'])
        unused = get_network_unused_count(network_info['range'])
        network = ipaddress.ip_network(network_info['range'])

        # Pretty print all network info
        print_network(network_info['range'], "Network:")
        print_network(network.netmask.exploded, "Netmask:")
        print_network(network_info['description'], "Description:")
        print_network(network_info['category'], "Category:")
        print_network(network_info['location'], "Location:")
        print_network(network_info['vlan'], "VLAN")
        print_network(network_info['dns_delegated'] if
                     network_info['dns_delegated'] else False, "DNS delegated:")
        print_network(network_info['frozen'] if network_info['frozen'] else False,
                     "Frozen")
        print_network_reserved(network_info['range'], network_info['reserved'])
        print_network(used, "Used addresses:")
        print_network_unused(unused)
        cli_info("printed network info for {}".format(network_info['range']))


network.add_command(
    prog='info',
    description='Display network info for one or more networks.',
    short_desc='Display network info.',
    callback=info,
    flags=[
        Flag('networks',
             description='One or more networks.',
             nargs='+',
             metavar='NETWORK'),
    ]
)


#########################################################
# Implementation of sub command 'list_unused_addresses' #
#########################################################

def list_unused_addresses(args):
    """Lists all the unused addresses for a network
    """
    if is_valid_ip(args.network) or is_valid_network(args.network):
        network = get_network(args.network)
        unused_addresses = available_ips_from_network(network)
    else:
        cli_warning("Not a valid ip or network")

    for address in unused_addresses:
        print("{1:<{0}}".format(25, address))


network.add_command(
    prog='list_unused_addresses',
    description='Lists all the unused addresses for a network',
    short_desc='Lists unused addresses',
    callback=list_unused_addresses,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)


#######################################################
# Implementation of sub command 'list_used_addresses' #
#######################################################

def list_used_addresses(args):
    """Lists all the used addresses for a network
    """
    if is_valid_ip(args.network):
        network = get_network(args.network)
        addresses = get_network_used_list(network['range'])
    elif is_valid_network(args.network):
        addresses = get_network_used_list(args.network)
    else:
        cli_warning("Not a valid ip or network")

    for address in addresses:
        host = resolve_ip(address)
        print("{1:<{0}}{2}".format(25, address, host))
    else:
        print("No used addresses.")


network.add_command(
    prog='list_used_addresses',
    description='Lists all the used addresses for a network',
    short_desc='Lists all the used addresses for a network',
    callback=list_used_addresses,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)


##########################################
# Implementation of sub command 'remove' #
##########################################

def remove(args):
    """Remove network
    """
    ipaddress.ip_network(args.network)
    host_list = get_network_used_list(args.network)
    if host_list:
        cli_warning("Network contains addresses that are in use. Remove hosts "
                    "before deletion")

    if not args.force:
        cli_warning("Must force.")

    delete(f"/networks/{args.network}")
    cli_info("removed network {}".format(args.network), True)


network.add_command(
    prog='remove',
    description='Remove network',
    short_desc='Remove network',
    callback=remove,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


################################################
# Implementation of sub command 'set_category' #
################################################

def set_category(args):
    """Set category tag for network
    """
    network = get_network(args.network)
    if not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")

    patch("/networks/{network['range']}", category=args.category)
    cli_info("updated category tag to '{}' for {}"
             .format(args.category, network['range']), True)


network.add_command(
    prog='set_category',
    description='Set category tag for network',
    short_desc='Set category tag for network',
    callback=set_category,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('category',
             description='Category tag.',
             metavar='CATEGORY-TAG'),
    ]
)


###################################################
# Implementation of sub command 'set_description' #
###################################################

def set_description(args):
    """Set description for network
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", description=args.description)
    cli_info("updated description to '{}' for {}".format(args.description,
                                                         network['range']), True)


network.add_command(
    prog='set_description',  # <network> <description>
    description='Set description for network',
    short_desc='Set description for network',
    callback=set_description,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('description',
             description='Network description.',
             metavar='DESC'),
    ]
)


#####################################################
# Implementation of sub command 'set_dns_delegated' #
#####################################################

def set_dns_delegated(args):
    """Set that DNS-administration is being handled elsewhere.
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", dns_delegated=True)
    cli_info("updated dns_delegated to '{}' for {}"
             .format(True, network['range']), print_msg=True)


network.add_command(
    prog='set_dns_delegated',
    description='Set that DNS-administration is being handled elsewhere.',
    short_desc='Set that DNS-administration is being handled elsewhere.',
    callback=set_dns_delegated,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)


##############################################
# Implementation of sub command 'set_frozen' #
##############################################

def set_frozen(args):
    """Freeze a network.
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", frozen=True)
    cli_info("updated frozen to '{}' for {}"
             .format(True, network['range']), print_msg=True)


network.add_command(
    prog='set_frozen',
    description='Freeze a network.',
    short_desc='Freeze a network.',
    callback=set_frozen,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)


################################################
# Implementation of sub command 'set_location' #
################################################

def set_location(args):
    """Set location tag for network
    """
    network = get_network(args.network)
    if not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    patch(f"/networks/{network['range']}", location=args.location)
    cli_info("updated location tag to '{}' for {}"
             .format(args.location, network['range']), True)


network.add_command(
    prog='set_location',
    description='Set location tag for network',
    short_desc='Set location tag for network',
    callback=set_location,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('location',
             description='Location tag.',
             metavar='LOCATION-TAG'),
    ]
)


################################################
# Implementation of sub command 'set_reserved' #
################################################

def set_reserved(args):
    """Set number of reserved hosts.
    """
    network = get_network(args.network)
    reserved = args.number
    patch(f"/networks/{network['range']}", reserved=reserved)
    cli_info("updated reserved to '{}' for {}"
             .format(reserved, network['range']), print_msg=True)


network.add_command(
    prog='set_reserved',
    description='Set number of reserved hosts.',
    short_desc='Set number of reserved hosts.',
    callback=set_reserved,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('number',
             description='Number of reserved hosts.',
             type=int,
             metavar='NUM'),
    ]
)


############################################
# Implementation of sub command 'set_vlan' #
############################################

def set_vlan(args):
    """Set VLAN for network
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", vlan=args.vlan)
    cli_info("updated vlan to {} for {}".format(args.vlan, network['range']),
             print_msg=True)


network.add_command(
    prog='set_vlan',  # <network> <vlan>
    description='Set VLAN for network',
    short_desc='Set VLAN for network',
    callback=set_vlan,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
        Flag('vlan',
             description='VLAN.',
             type=int,
             metavar='VLAN'),
    ]
)


#######################################################
# Implementation of sub command 'unset_dns_delegated' #
#######################################################

def unset_dns_delegated(args):
    """Set that DNS-administration is not being handled elsewhere.
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", dns_delegated=False)
    cli_info("updated dns_delegated to '{}' for {}"
             .format(False, network['range']), print_msg=True)


network.add_command(
    prog='unset_dns_delegated',
    description='Set that DNS-administration is not being handled elsewhere.',
    short_desc='Set that DNS-administration is not being handled elsewhere.',
    callback=unset_dns_delegated,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)


################################################
# Implementation of sub command 'unset_frozen' #
################################################

def unset_frozen(args):
    """Unfreeze a network.
    """
    network = get_network(args.network)
    patch(f"/networks/{network['range']}", frozen=False)
    cli_info("updated frozen to '{}' for {}"
             .format(False, network['range']), print_msg=True)


network.add_command(
    prog='unset_frozen',
    description='Unfreeze a network.',
    short_desc='Unfreeze a network.',
    callback=unset_frozen,
    flags=[
        Flag('network',
             description='Network.',
             metavar='NETWORK'),
    ]
)
