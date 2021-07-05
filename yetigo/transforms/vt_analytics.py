import json
from canari.maltego.message import Entity

from canari.maltego.transform import Transform
from dateutil import parser

from yetigo.transforms.entities import Hash, Domain, Ip, Hostname, Url
from yetigo.transforms.utils import (
    get_yeti_connection,
    get_av_sig,
    get_hash_entities,
    get_status_domains,
    get_sample_by_ip_vt,
    get_hostnames_by_ip_vt,
    get_ips_by_hostname_vt,
    run_oneshot,
    get_observable,
)


class VTHashReport(Transform):
    input_type = Hash
    display_name = "[YT] Report Hash Virustotal"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT Hash Report", request, config)
        if res:
            virus_res = res["nodes"][0]
            context_vt = list(
                filter(
                    lambda x: x["source"] == "VirusTotal", res["nodes"][0]["context"]
                )
            )
            context_filter = sorted(
                context_vt, key=lambda x: parser.parse(x["last_seen"])
            )
            last_context = None
            if len(context_filter) > 0:
                last_context = context_filter[0]
                entity.malicious = last_context["malicious"]
                entity.undetected = last_context["undetected"]
                entity.suspicious = last_context["suspicious"]
                entity.magic = last_context["magic"]
                response += entity
            for r in res["links"]:
                obs = get_observable(r["src"]["id"], config)
                h = Hash(obs["value"])
                h.malicious = last_context["malicious"]
                h.undetected = last_context["undetected"]
                h.suspicious = last_context["suspicious"]
                h.magic = last_context["magic"]
                response += h
            return response


class VTHashIPContacted(Transform):

    input_type = Hash
    display_name = "[YT] VT IP Contacted"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT IP Contacted", request, config)

        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            ip = Ip(obs["value"])
            response += ip
        return response


class VTHashDomainContacted(Transform):

    input_type = Hash
    display_name = "[YT] VT Domain Contacted"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT Domain Contacted", request, config)

        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            hostname = Hostname(obs["value"])
            hostname.link_label = "first_seen: %s last_seen: %s" % (
                r["first_seen"],
                r["last_seen"],
            )
            response += hostname
        return response


class VTHashUrlsContacted(Transform):

    input_type = Hash
    display_name = "[YT] VT Urls Contacted"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT Domain Contacted", request, config)

        for r in res["links"]:
            obs = get_observable(r["src"]["id"])
            url = Url(obs["value"])
            context_vt = list(
                filter(lambda x: x["source"] == "VirusTotal", obs["context"])
            )
            context_filter = sorted(
                context_vt, key=lambda x: parser.parse(x["last_seen"])
            )[0]
            url.link_label = "first seen: %s last modification: %s" % (
                context_filter["first_seen"],
                context_filter["last_modification_date"],
            )
            response += url
        return response


class VTIPassiveDNS(Transform):

    input_type = Ip
    display_name = "[YT] VT IP Resolution"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT IP Resolution", request, config)
        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            hostname = Hostname(obs["value"])

            context_vt = [
                (entity.value, c[entity.value])
                for c in obs["context"]
                if c["source"] == "VirusTotal PDNS" and entity.value in c
            ]
            last_resolution = sorted(context_vt, key=lambda x: parser.parse(x[1]))
            hostname.link_label = "last_resolution: %s" % last_resolution[0][1]
            response += hostname
        return response


class VTDomainPassiveDNS(Transform):

    input_type = Hostname
    display_name = "[YT] VT Domain Resolution"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT Domain Resolution", request, config)
        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            ip = Ip(obs["value"])

            context_vt = [
                (entity.value, c[entity.value])
                for c in obs["context"]
                if c["source"] == "VirusTotal PDNS" and entity.value in c
            ]
            last_resolution = sorted(context_vt, key=lambda x: parser.parse(x[1]))

            ip.link_label = "last_resolution: %s" % last_resolution[0][1]

            response += ip
        return response


class VTIPComFiles(Transform):
    input_type = Ip
    display_name = "[YT] VT IP Com files"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT IP Com files", request, config)
        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            new_file = Hash(obs["value"])
            if "tags" in obs:
                new_file.tags = [t["name"] for t in obs["tags"]]
            response += new_file
        return response


class VTDomainComFiles(Transform):
    input_type = Hostname
    display_name = "[YT] VT Domain Com Files"

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot("VT Com files domain", request, config)
        for r in res["links"]:
            obs = get_observable(r["src"]["id"], config)
            new_file = Hash(obs["value"])
            if "tags" in obs:
                new_file.tags = [t["name"] for t in obs["tags"]]
            response += new_file
        return response
