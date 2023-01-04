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
        # TODO: Refactor this monstrosity of a test :) make it more dynamic

        async with self.getTestCore() as core:
            await core.nodes("[ inet:fqdn = example.com ]")
            msgs = await core.stormlist(
                "inet:fqdn=example.com | lctih.pivoting.sources"
            )
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                "https://www.google.com/search?q=site:example.com", msgs
            )
            self.stormIsInPrint('https://www.google.com/search?q="example.com"', msgs)
            self.stormIsInPrint("https://duckduckgo.com/?q=site:example.com", msgs)
            self.stormIsInPrint('https://duckduckgo.com/?q="example.com"', msgs)
            self.stormIsInPrint(
                "https://otx.alienvault.com/browse/global/pulses?q=example.com", msgs
            )
            self.stormIsInPrint(
                "https://www.virustotal.com/gui/search/example.com", msgs
            )
            self.stormIsInPrint("https://orkl.eu/search", msgs)
            self.stormIsInPrint("https://www.threatminer.org/", msgs)
            self.stormIsInPrint(
                'https://twitter.com/search?q="example.com"&f=live', msgs
            )
            self.stormIsInPrint('https://github.com/search?q="example.com"', msgs)
            self.stormIsInPrint("https://completedns.com/dns-history/", msgs)
            self.stormIsInPrint(
                "https://community.riskiq.com/research?query=example.com", msgs
            )
            self.stormIsInPrint("https://urlscan.io/search/#example.com", msgs)

            await core.nodes("[ inet:ipv4 = 1.2.3.4 ]")
            msgs = await core.stormlist("inet:ipv4 = 1.2.3.4 | lctih.pivoting.sources")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("https://www.google.com/search?q=site:1.2.3.4", msgs)
            self.stormIsInPrint('https://www.google.com/search?q="1.2.3.4"', msgs)
            self.stormIsInPrint("https://duckduckgo.com/?q=site:1.2.3.4", msgs)
            self.stormIsInPrint('https://duckduckgo.com/?q="1.2.3.4"', msgs)
            self.stormIsInPrint(
                "https://otx.alienvault.com/browse/global/pulses?q=1.2.3.4", msgs
            )
            self.stormIsInPrint("https://www.virustotal.com/gui/search/1.2.3.4", msgs)
            self.stormIsInPrint("https://orkl.eu/search", msgs)
            self.stormIsInPrint("https://www.threatminer.org/", msgs)
            self.stormIsInPrint("https://ipinfo.io/1.2.3.4", msgs)
            self.stormIsInPrint('https://twitter.com/search?q="1.2.3.4"&f=live', msgs)
            self.stormIsInPrint('https://github.com/search?q="1.2.3.4"', msgs)
            self.stormIsInPrint(
                "https://community.riskiq.com/research?query=1.2.3.4", msgs
            )

            await core.nodes("[ hash:md5 =  393f175d3782d4f6b1d215bd0f31a777  ]")
            msgs = await core.stormlist(
                "hash:md5 =  393f175d3782d4f6b1d215bd0f31a777 | lctih.pivoting.sources"
            )
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(
                'https://www.google.com/search?q="393f175d3782d4f6b1d215bd0f31a777"',
                msgs,
            )
            self.stormIsInPrint(
                "https://otx.alienvault.com/browse/global/pulses?q=393f175d3782d4f6b1d215bd0f31a777",
                msgs,
            )
            self.stormIsInPrint(
                "https://www.virustotal.com/gui/search/393f175d3782d4f6b1d215bd0f31a777",
                msgs,
            )
            self.stormIsInPrint("https://orkl.eu/search", msgs)
            self.stormIsInPrint("https://www.threatminer.org/", msgs)
            self.stormIsInPrint("https://www.vx-underground.org/malware.html", msgs)
            self.stormIsInPrint(
                'https://twitter.com/search?q="393f175d3782d4f6b1d215bd0f31a777"&f=live',
                msgs,
            )
            self.stormIsInPrint(
                'https://github.com/search?q="393f175d3782d4f6b1d215bd0f31a777"', msgs
            )
            self.stormIsInPrint(
                "https://community.riskiq.com/research?query=393f175d3782d4f6b1d215bd0f31a777",
                msgs,
            )

            self.stormIsInPrint(
                "https://www.hybrid-analysis.com/search?query=393f175d3782d4f6b1d215bd0f31a777",
                msgs,
            )

            self.stormIsInPrint("https://virusshare.com", msgs)

            await core.nodes(
                "[ hash:sha1 =  e281722ebc73be5ecfca93b3395ba745ec354333  ]"
            )
            msgs = await core.stormlist(
                "hash:sha1 =  e281722ebc73be5ecfca93b3395ba745ec354333 | lctih.pivoting.sources"
            )
            self.stormHasNoWarnErr(msgs)

            await core.nodes(
                "[ hash:sha256 =  d22df444e867fdf647f6757547b2b75968453c3bb398a5d94c5e17a5e57af7f6  ]"
            )
            msgs = await core.stormlist(
                "hash:sha256 =  d22df444e867fdf647f6757547b2b75968453c3bb398a5d94c5e17a5e57af7f6 | lctih.pivoting.sources"
            )
            self.stormHasNoWarnErr(msgs)

    async def test_lctih_update_misp_clusters(self):

        async with self.getTestCore() as core:

            # TODO: Finish and refactor this test

            nodes = await core.nodes("lctih.update.misp.clusters")
            msgs = await core.stormlist("lctih.update.misp.clusters")

            self.stormIsInPrint("Threat Actor", msgs)

            self.stormHasNoWarnErr(msgs)
