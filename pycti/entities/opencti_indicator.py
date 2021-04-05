# coding: utf-8

from __future__ import annotations

import json

from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from pycti import OpenCTIApiClient


class Indicator:
    """Main Indicator class for OpenCTI

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    """

    def __init__(self, opencti: OpenCTIApiClient):
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        edges {
                            node {
                                id
                                value
                                color
                            }
                        }
                    }
                }
                ... on Organization {
                    x_opencti_organization_type
                    x_opencti_reliability
                }
                ... on Individual {
                    x_opencti_firstname
                    x_opencti_lastname
                }
            }
            objectMarking {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        definition_type
                        definition
                        created
                        modified
                        x_opencti_order
                        x_opencti_color
                    }
                }
            }
            objectLabel {
                edges {
                    node {
                        id
                        value
                        color
                    }
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                    }
                }
            }
            revoked
            confidence
            created
            modified
            pattern_type
            pattern_version
            pattern
            name
            description
            indicator_types
            valid_from
            valid_until
            x_opencti_score
            x_opencti_detection
            x_opencti_main_observable_type
            x_mitre_platforms
            observables {
                edges {
                    node {
                        id
                        observable_value
                    }
                }
            }
            killChainPhases {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        kill_chain_name
                        phase_name
                        x_opencti_order
                        created
                        modified
                    }
                }
            }
        """

    def list(self, **kwargs):
        """List Indicator objects

        The list method accepts the following kwargs:

        :param list filters: (optional) the filters to apply
        :param str search: (optional) a search keyword to apply for the listing
        :param int first: (optional) return the first n rows from the `after` ID
                            or the beginning if not set
        :param str after: (optional) OpenCTI object ID of the first row for pagination
        :param str orderBy: (optional) the field to order the response on
        :param bool orderMode: (optional) either "`asc`" or "`desc`"
        :param list customAttributes: (optional) list of attributes keys to return
        :param bool getAll: (optional) switch to return all entries (be careful to use this without any other filters)
        :param bool withPagination: (optional) switch to use pagination

        :return: List of Indicators
        :rtype: list
        """

        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 500)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        if get_all:
            first = 100

        self.opencti.log(
            "info", "Listing Indicators with filters " + json.dumps(filters) + "."
        )
        query = (
            """
            query Indicators($filters: [IndicatorsFiltering], $search: String, $first: Int, $after: ID, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode) {
                indicators(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )
        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["indicators"])
            final_data = final_data + data
            while result["data"]["indicators"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["indicators"]["pageInfo"]["endCursor"]
                self.opencti.log("info", "Listing Indicators after " + after)
                result = self.opencti.query(
                    query,
                    {
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(result["data"]["indicators"])
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["indicators"], with_pagination
            )

    def read(self, **kwargs):
        """Read an Indicator object

        read can be either used with a known OpenCTI entity `id` or by using a
        valid filter to search and return a single Indicator entity or None.

        The list method accepts the following kwargs.

        Note: either `id` or `filters` is required.

        :param str id: the id of the Threat-Actor
        :param list filters: the filters to apply if no id provided

        :return: Indicator object
        :rtype: Indicator
        """

        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.log("info", "Reading Indicator {" + id + "}.")
            query = (
                """
                query Indicator($id: String!) {
                    indicator(id: $id) {
                        """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else self.properties
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(result["data"]["indicator"])
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.log(
                "error", "[opencti_indicator] Missing parameters: id or filters"
            )
            return None

    def create(
        self,
        stix_id: Optional[str] = None,
        createdBy: Optional[str] = None,
        objectMarking: Optional[str] = None,
        objectLabel: List[Optional[str]] = None,
        externalReferences: List[Optional[str]] = None,
        revoked: Optional[bool] = None,
        confidence: Optional[int] = None,
        lang: Optional[str] = None,
        created: Optional[str] = None,
        modified: Optional[str] = None,
        pattern_type: Optional[str] = None,
        pattern_version: Optional[str] = None,
        pattern: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        indicator_types: List[Optional[str]] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        x_opencti_score: Optional[int] = 50,
        x_opencti_detection: Optional[bool] = False,
        x_opencti_main_observable_type: Optional[str] = None,
        killChainPhases: List[Optional[str]] = None,
        update=False,
        **kwargs
    ) -> Optional[Dict]:
        """Indicators contain a pattern that can be used to detect suspicious or malicious cyber
        activity. For example, an Indicator may be used to represent a set of malicious domains
        and use the STIX Patterning Language to specify these domains.

        :param stix_id: The stix_id property uniquely identifies this object.
        :param createdBy: The created_by_ref property specifies the id property of the identity
            object that describes the entity that created this object.
        :param objectMarking: The data markings represent restrictions, permissions, and other
            guidance for how data can be used and shared.
        :param objectLabel: The labels property specifies a set of terms used to describe this
            object. The terms are user-defined or trust-group defined and their meaning is
            outside the scope of this specification and MAY be ignored.
            Where an object has a specific property defined in the specification for
            characterizing subtypes of that object, the labels property MUST NOT be used for
            that purpose.
            For example, the Malware SDO has a property malware_types that contains a list of
            Malware subtypes (dropper, RAT, etc.). In this example, the labels property cannot
            be used to describe these Malware subtypes.
        :param externalReferences: The external_references property specifies a list of external
            references which refers to non-STIX information. This property is used to provide
            one or more URLs, descriptions, or IDs to records in other systems.
        :param revoked: The revoked property is only used by STIX Objects that support
            versioning and indicates whether the object has been revoked.
            Revoked objects are no longer considered valid by the object creator. Revoking an
            object is permanent; future versions of the object with this id MUST NOT be created.
        :param confidence: The confidence property identifies the confidence that the creator
            has in the correctness of their data. The confidence value MUST be a number in the
            range of 0-100.
            If the confidence property is not present, then the confidence of the content is
            unspecified.
        :param lang: The lang property identifies the language of the text content in this
            object. When present, it MUST be a language code conformant to [RFC5646]. If the
            property is not present, then the language of the content is en (English).
            This property SHOULD be present if the object type contains translatable text
            properties (e.g. name, description).
            The language of individual fields in this object MAY be overridden by the lang
            property in granular markings.
        :param created: The created property represents the time at which the object was
            originally created.
        :param modified: The modified property is only used by STIX Objects that support
            versioning and represents the time that this particular version of the object was
            last modified.
            The object creator can use the time it deems most appropriate as the time this
            version of the object was modified. The minimum precision MUST be milliseconds
            (three digits after the decimal place in seconds), but MAY be more precise.
            If the created property is defined, then the value of the modified property for a
            given object version MUST be later than or equal to the value of the created
            property. Object creators MUST set the modified property when creating a new version
            of an object if the created property was set.
        :param pattern_type: The pattern language used in this indicator
        :param pattern_version: The version of the pattern language that is used for the data in
            the pattern property which MUST match the type of pattern data included in the
            pattern property.
        :param pattern: The detection pattern for this Indicator MAY be expressed
            as a STIX Pattern as specified in section 9 or another appropriate language such as
            SNORT, YARA, etc
        :param name: A name used to identify the Indicator.
        :param description: A description that provides more details and context about the
            Indicator, potentially including its purpose and its key characteristics.
        :param indicator_types: A set of categorizations for this indicator.
        :param valid_from: The time from which this Indicator is considered a valid indicator of
            the behaviors it is related or represents.
        :param valid_until: The time at which this Indicator should no longer be considered a
            valid indicator of the behaviors it is related to or represents. If the valid_until
            property is omitted, then there is no constraint on the latest time for which the
            Indicator is valid.
        :param x_opencti_score: [description], defaults to 50.
        :param x_opencti_detection: [description].
        :param x_opencti_main_observable_type: Type of the observable.
        :param killChainPhases: The kill chain phase(s) to which this Indicator corresponds.
        :param update: Update the Indicator if it already exists.
        :return: Indicator object.
        """
        created_by = createdBy
        object_marking = objectMarking
        object_label = objectLabel
        external_references = externalReferences
        kill_chain_phases = killChainPhases

        if (
            name is not None
            and pattern is not None
            and x_opencti_main_observable_type is not None
        ):
            if x_opencti_main_observable_type == "File":
                x_opencti_main_observable_type = "StixFile"
            self.opencti.log("info", "Creating Indicator {" + name + "}.")
            query = """
                mutation IndicatorAdd($input: IndicatorAddInput) {
                    indicatorAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                        observables {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                }
                            }
                        }
                    }
                }
            """
            if pattern_type is None:
                pattern_type = "stix2"
            result = self.opencti.query(
                query,
                {
                    "input": {
                        "stix_id": stix_id,
                        "createdBy": created_by,
                        "objectMarking": object_marking,
                        "objectLabel": object_label,
                        "externalReferences": external_references,
                        "revoked": revoked,
                        "confidence": confidence,
                        "lang": lang,
                        "created": created,
                        "modified": modified,
                        "pattern_type": pattern_type,
                        "pattern_version": pattern_version,
                        "pattern": pattern,
                        "name": name,
                        "description": description,
                        "indicator_types": indicator_types,
                        "valid_until": valid_until,
                        "valid_from": valid_from,
                        "x_opencti_score": x_opencti_score,
                        "x_opencti_detection": x_opencti_detection,
                        "x_opencti_main_observable_type": x_opencti_main_observable_type,
                        "killChainPhases": kill_chain_phases,
                        "update": update,
                    }
                },
            )
            return self.opencti.process_multiple_fields(result["data"]["indicatorAdd"])
        else:
            self.opencti.log(
                "error",
                "[opencti_indicator] Missing parameters: name or pattern or x_opencti_main_observable_type",
            )
            return None

    def add_stix_cyber_observable(self, **kwargs):
        """
        Add a Stix-Cyber-Observable object to Indicator object (based-on)

        :param id: the id of the Indicator
        :param indicator: Indicator object
        :param stix_cyber_observable_id: the id of the Stix-Observable

        :return: Boolean True if there has been no import error
        """
        id = kwargs.get("id", None)
        indicator = kwargs.get("indicator", None)
        stix_cyber_observable_id = kwargs.get("stix_cyber_observable_id", None)
        if id is not None and stix_cyber_observable_id is not None:
            if indicator is None:
                indicator = self.read(id=id)
            if indicator is None:
                self.opencti.log(
                    "error",
                    "[opencti_indicator] Cannot add Object Ref, indicator not found",
                )
                return False
            if stix_cyber_observable_id in indicator["observablesIds"]:
                return True
            else:
                self.opencti.log(
                    "info",
                    "Adding Stix-Observable {"
                    + stix_cyber_observable_id
                    + "} to Indicator {"
                    + id
                    + "}",
                )
                query = """
                    mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                        stixCoreRelationshipAdd(input: $input) {
                            id
                        }
                    }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "fromId": id,
                            "toId": stix_cyber_observable_id,
                            "relationship_type": "based-on",
                        },
                    },
                )
                return True
        else:
            self.opencti.log(
                "error",
                "[opencti_indicator] Missing parameters: id and stix cyber_observable_id",
            )
            return False

    def import_from_stix2(self, **kwargs):
        """
        Import an Indicator object from a STIX2 object

        :param stixObject: the Stix-Object Indicator
        :param extras: extra dict
        :param bool update: set the update flag on import

        :return: Indicator object
        :rtype: Indicator
        """
        stix_object = kwargs.get("stixObject", None)
        extras = kwargs.get("extras", {})
        update = kwargs.get("update", False)
        if stix_object is not None:
            return self.create(
                stix_id=stix_object["id"],
                createdBy=extras["created_by_id"]
                if "created_by_id" in extras
                else None,
                objectMarking=extras["object_marking_ids"]
                if "object_marking_ids" in extras
                else None,
                objectLabel=extras["object_label_ids"]
                if "object_label_ids" in extras
                else [],
                externalReferences=extras["external_references_ids"]
                if "external_references_ids" in extras
                else [],
                revoked=stix_object["revoked"] if "revoked" in stix_object else None,
                confidence=stix_object["confidence"]
                if "confidence" in stix_object
                else None,
                lang=stix_object["lang"] if "lang" in stix_object else None,
                created=stix_object["created"] if "created" in stix_object else None,
                modified=stix_object["modified"] if "modified" in stix_object else None,
                pattern_type=stix_object["pattern_type"]
                if "pattern_type" in stix_object
                else None,
                pattern_version=stix_object["pattern_version"]
                if "pattern_version" in stix_object
                else None,
                pattern=stix_object["pattern"] if "pattern" in stix_object else "",
                name=stix_object["name"]
                if "name" in stix_object
                else stix_object["pattern"],
                description=self.opencti.stix2.convert_markdown(
                    stix_object["description"]
                )
                if "description" in stix_object
                else "",
                indicator_types=stix_object["indicator_types"]
                if "indicator_types" in stix_object
                else None,
                valid_from=stix_object["valid_from"]
                if "valid_from" in stix_object
                else None,
                valid_until=stix_object["valid_until"]
                if "valid_until" in stix_object
                else None,
                x_opencti_score=stix_object["x_opencti_score"]
                if "x_opencti_score" in stix_object
                else 50,
                x_opencti_detection=stix_object["x_opencti_detection"]
                if "x_opencti_detection" in stix_object
                else False,
                x_opencti_main_observable_type=stix_object[
                    "x_opencti_main_observable_type"
                ]
                if "x_opencti_main_observable_type" in stix_object
                else "Unknown",
                killChainPhases=extras["kill_chain_phases_ids"]
                if "kill_chain_phases_ids" in extras
                else None,
                update=update,
            )
        else:
            self.opencti.log(
                "error", "[opencti_attack_pattern] Missing parameters: stixObject"
            )
