import os

import synapse.tests.utils as s_test

dirname = os.path.abspath(os.path.dirname(__file__))


class LctihTest(s_test.StormPkgTest):

    pkgprotos = (os.path.join(dirname, "lctih.yaml"),)

    async def test_lctih_explore(self):

        async with self.getTestCore() as core:

            await core.nodes("[ inet:dns:a = (example.com, 1.2.3.4) ]")
            await core.nodes('[ inet:fqdn = "example.com" +#xxx.yyy.zzz ]')
            await core.nodes(
                '[ inet:fqdn = "example.com" +(seen)> {[inet:url="http://supersecnews.com/example"]} ]'
            )
            await core.nodes(
                '[ inet:fqdn = "example.com" <(refs)+ {[inet:url="http://cybersecfirm.com/report.pdf"]} ]'
            )

            nodes = await core.nodes("inet:fqdn=example.com | lctih.explore")

            self.len(7, nodes)

            self.eq(
                [node.ndef for node in nodes],
                [
                    ("inet:fqdn", "example.com"),
                    ("inet:fqdn", "com"),
                    ("inet:url", "http://supersecnews.com/example"),
                    ("inet:dns:a", ("example.com", 16909060)),
                    ("inet:fqdn", "example.com"),
                    ("inet:url", "http://cybersecfirm.com/report.pdf"),
                    ("syn:tag", "xxx.yyy.zzz"),
                ],
            )

            # Is there a better way than to have to run the query again in order to test the print output?
            msgs = await core.stormlist("inet:fqdn=example.com | lctih.explore")

            self.stormIsInPrint("Input node", msgs)
            self.stormIsInPrint("Pivoting out and walking", msgs)
            self.stormIsInPrint("Pivoting in and walking", msgs)
            self.stormIsInPrint("Pivoting to tags", msgs)

            self.stormHasNoWarnErr(msgs)

    async def test_lctih_pivoting_sources(self):
        async with self.getTestCore() as core:
            msgs = []
            searchable_variable_names = []

            fqdn = "example.com"
            await core.nodes(f"[ inet:fqdn = {fqdn} ]")
            fqdn_msgs = await core.stormlist(
                f"inet:fqdn={fqdn} | lctih.pivoting.sources --external"
            )
            msgs.extend(fqdn_msgs)
            searchable_variable_names.append("fqdn")

            ipv4 = "1.2.3.4"
            await core.nodes(f"[ inet:ipv4 = {ipv4} ]")
            ipv4_msgs = await core.stormlist(
                f"inet:ipv4={ipv4} | lctih.pivoting.sources --external"
            )
            msgs.extend(ipv4_msgs)
            searchable_variable_names.append("ipv4")

            md5 = "393f175d3782d4f6b1d215bd0f31a777"
            await core.nodes(f"[ hash:md5 = {md5} ]")
            md5_msgs = await core.stormlist(
                f"hash:md5={md5} | lctih.pivoting.sources --external"
            )
            msgs.extend(md5_msgs)
            searchable_variable_names.append("md5")

            sha1 = "e281722ebc73be5ecfca93b3395ba745ec354333"
            await core.nodes(f"[ hash:sha1 =  {sha1} ]")
            sha1_msgs = await core.stormlist(
                f"hash:sha1={sha1} | lctih.pivoting.sources --external"
            )
            msgs.extend(sha1_msgs)
            searchable_variable_names.append("sha1")

            sha256 = "d22df444e867fdf647f6757547b2b75968453c3bb398a5d94c5e17a5e57af7f6"
            await core.nodes(f"[ hash:sha256 = {sha256} ]")
            sha256_msgs = await core.stormlist(
                f"hash:sha256={sha256} | lctih.pivoting.sources --external"
            )
            msgs.extend(sha256_msgs)
            searchable_variable_names.append("sha256")

            email = "test@example.com"
            await core.nodes(f"[ inet:email = {email} ]")
            email_msgs = await core.stormlist(
                f"inet:email={email} | lctih.pivoting.sources --external"
            )
            msgs.extend(email_msgs)
            searchable_variable_names.append("email")

            url = "https://example.com"
            await core.nodes(f"[ inet:url = '{url}' ]")
            url_msgs = await core.stormlist(
                f"inet:url='{url}' | lctih.pivoting.sources --external"
            )
            msgs.extend(url_msgs)
            searchable_variable_names.append("url")

            yara_rule = 'rule test {strings: $a = "test" condition: $a}'
            await core.nodes(f"[ it:app:yara:rule = * :text='{yara_rule}' ]")
            yara_rule_msgs = await core.stormlist(
                f"it:app:yara:rule:text ~= test | lctih.pivoting.sources --external"
            )
            msgs.extend(yara_rule_msgs)

            # TODO: code snippets or strings + custom nodes?

            self.stormHasNoWarnErr(msgs)

            sources_to_variable_names = {
                "https://www.google.com/search?q=site:{value}": ["fqdn", "ipv4"],
                'https://www.google.com/search?q="{value}"': searchable_variable_names,
                "https://duckduckgo.com/?q=site:{value}": ["fqdn", "ipv4"],
                'https://duckduckgo.com/?q="{value}"': searchable_variable_names,
                "https://otx.alienvault.com/browse/global/pulses?q={value}": searchable_variable_names,
                "https://www.virustotal.com/gui/search/{value}": searchable_variable_names,
                "https://labs.inquest.net/": searchable_variable_names,
                "https://orkl.eu/search": searchable_variable_names,
                "https://www.threatminer.org/": searchable_variable_names,
                'https://twitter.com/search?q="{value}"&f=live': searchable_variable_names,
                'https://github.com/search?q="{value}"': searchable_variable_names,
                "https://pulsedive.com/": searchable_variable_names,
                "https://hn.algolia.com/?dateRange=all&page=0&prefix=true&query={value}&sort=byPopularity&type=all": searchable_variable_names,
                "https://urlscan.io/search/#{value}": ["fqdn", "ipv4"],
                'https://search.censys.io/search?resource=hosts&q="{value}"': [
                    "fqdn",
                    "ipv4",
                ],
                'https://search.censys.io/certificates?q="{value}"': ["fqdn", "ipv4"],
                "https://intelx.io/?s={value}": ["fqdn", "ipv4", "email"],
                "https://completedns.com/dns-history/": ["fqdn"],
                "gau {value}": ["fqdn"],
                "https://www.shodan.io/search?query=hostname:{value}": ["fqdn"],
                "https://ipinfo.io/{value}": ["ipv4"],
                "https://www.shodan.io/search?query=ip:{value}": ["ipv4"],
                "https://who.is/whois-ip/ip-address/{value}": ["ipv4"],
                "https://crt.sh/?q={value}": ["fqdn"],
                "https://web.archive.org/web/*/{value}*": ["fqdn"],
                "https://archive.ph/*.{value}": ["fqdn"],
                "https://securitytrails.com/domain/{value}/history/a": ["fqdn"],
                "https://www.whoxy.com/{value}": ["fqdn"],
                "https://www.whoxy.com/email/{value}": ["email"],
                "https://viewdns.info/reversewhois/?q={value}": ["email"],
                "https://www.robtex.com/dns-lookup/{value}": ["fqdn"],
                "https://virusshare.com": ["md5", "sha1", "sha256"],
                "https://app.any.run/submissions": ["md5", "sha1", "sha256"],
                "https://bazaar.abuse.ch/browse/": ["md5", "sha1", "sha256"],
                "https://hashlookup.circl.lu/": ["md5", "sha1", "sha256"],
                "https://malshare.com/search.php?query={value}": [
                    "md5",
                    "sha1",
                    "sha256",
                ],
                "https://tria.ge/s?q={value}": ["md5", "sha1", "sha256"],
                "https://www.vx-underground.org/malware.html": [
                    "md5",
                    "sha1",
                    "sha256",
                ],
                "https://www.hybrid-analysis.com/search?query={value}": [
                    "md5",
                    "sha1",
                    "sha256",
                ],
                "https://community.riskiq.com/research?query={value}": searchable_variable_names,
                "https://www.hybrid-analysis.com/yara-search": ["yara_rule"],
                "https://bazaar.abuse.ch/account/": ["yara_rule"],
                "https://urlhaus.abuse.ch/browse.php?search={value}": ["url"],
            }

            for source, variable_names in sources_to_variable_names.items():
                for variable_name in variable_names:
                    self.stormIsInPrint(
                        source.format(value=locals().get(variable_name)),
                        locals().get(variable_name + "_msgs"),
                    )

    async def test_lctih_update_misp_clusters(self):

        async with self.getTestCore() as core:

            await core.nodes("lctih.update.misp.clusters")

            # TODO: Test a sample of the nodes. This will break if the MISP cluster changes.

            # Same here. Is there a way to avoid to run it two times only for checking the output?
            msgs = await core.stormlist("lctih.update.misp.clusters")
            self.stormIsInPrint("Ingesting the Threat Actors MISP Galaxy", msgs)
            self.stormHasNoWarnErr(msgs)
