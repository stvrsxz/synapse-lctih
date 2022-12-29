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
