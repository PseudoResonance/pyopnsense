# Copyright 2022 Patrick Carr
#
# This file is part of pyopnsense
#
# pyopnsense is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pyopnsense is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyopnsense. If not, see <http://www.gnu.org/licenses/>.

from pyopnsense import client


class FirewallClient(client.OPNClient):
    """A client for interacting with the firewall endpoint.

    :param str api_key: The API key to use for requests
    :param str api_secret: The API secret to use for requests
    :param str base_url: The base API endpoint for the OPNsense deployment
    :param int timeout: The timeout in seconds for API requests
    """

    def get_automation_rules(self):
        """Return the current firewall automation rules.

        :returns: A dict representing the current firewall rules
        :rtype: dict
        """
        return self._get("firewall/filter/searchRule")

    def get_rule_status(self, uuid):
        """Return the current status (enabled/disabled) of a specific firewall
        rule

        Parameter:  uuid

        :returns: A dict representing the current state of a firewall rule
        :rtype: dict
        """

        return self._get(f"firewall/filter/getRule/{uuid}")

    def toggle_rule(self, uuid):
        """Function to toggle a specific rule by uuid

        :returns: A dict representing the new status of the rule
        :rtype: dict
        """
        return self._post(f"firewall/filter/toggleRule/{uuid}", "")

    def apply_rules(self):
        """Function to apply changes to rules."""
        self._post("firewall/filter/apply/", "")

    def get_categories(self):
        """Get a list of firewall categories

        :returns: A dict representing all categories
        :rtype: dict
        """
        return self._post("firewall/category/searchItem",
                          {"current": 1, "rowCount": -1, "sort": {}, "searchPhrase": ""})

    def get_aliases(self, searchType: list[str] = [], searchCategories: list[str] = []):
        """Get a list of firewall aliases

        :returns: A dict representing all aliases
        :rtype: dict
        """
        return self._post("firewall/alias/searchItem",
                          {"current": 1, "rowCount": -1, "sort": {}, "searchPhrase": "", "type": searchType, "category": searchCategories})

    def add_alias(self, alias: dict):
        """Adds a new firewall alias

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post("firewall/alias/addItem",
                          alias)

    def set_alias(self, uuid: str, alias: dict):
        """Sets the options of a firewall alias

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post(f"firewall/alias/setItem/{uuid}",
                          alias)

    def del_alias(self, uuid: str):
        """Deletes a firewall alias

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post(f"firewall/alias/delItem/{uuid}", {})

    def apply_aliases(self):
        """Applies all updated aliases

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post("firewall/alias/set", {})

    def get_source_nat(self, searchCategories: list[str] = []):
        """Get a list of source NAT rules

        :returns: A dict representing all source NAT rules
        :rtype: dict
        """
        return self._post("firewall/source_nat/search_rule", {"current": 1, "rowCount": -1, "sort": {}, "searchPhrase": "", "category": searchCategories})

    def add_source_nat(self, rule: dict):
        """Adds a NAT port forward

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post("firewall/source_nat/add_rule", rule)

    def del_source_nat(self, uuid: str):
        """Deletes a NAT port forward

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post(f"firewall/source_nat/del_rule/{uuid}", {})

    def get_filter_rule(self, searchCategories: list[str] = []):
        """Get a list of filter rules

        :returns: A dict representing all filter rules
        :rtype: dict
        """
        return self._post("firewall/filter/search_rule", {"current": 1, "rowCount": -1, "sort": {}, "searchPhrase": "", "category": searchCategories})

    def add_filter_rule(self, rule: dict):
        """Adds a filter rule

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post("firewall/filter/add_rule", rule)

    def del_filter_rule(self, uuid: str):
        """Deletes a filter rule

        :returns: A dict representing the result of the operation
        :rtype: dict
        """
        return self._post(f"firewall/filter/del_rule/{uuid}", {})
