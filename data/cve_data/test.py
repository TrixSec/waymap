import unittest

from cve_data import CVEData
# from cve_data import CVEDataException

class TestCVEData(unittest.TestCase):
    """
    Unit tests for CVEData
    """
    def setUp(self):
        # Get an instance of CVEData
        self.cve_data = CVEData()

    def test_get_cve(self):
        """
        Test the get_cve method

        Verify that the get_cve method returns a CVE object with the
        correct properties.
        """
        cve = self.cve_data.get_cve('CVE-2017-5638')
        self.assertIsNotNone(cve)
        self.assertEqual(cve.id, 'CVE-2017-5638')
        self.assertEqual(cve.summary, 'Apache Struts 2 2.3.16 and 2.5.x before 2.5.10.1 have a "Possible Remote Code Execution" (RCE) vulnerability.')
        self.assertEqual(cve.published, '2017-03-07')
        self.assertEqual(cve.modified, '2017-03-09')
        self.assertEqual(cve.access, {'authentication': 'NONE', 'complexity': 'MEDIUM', 'vector': 'NETWORK'})
        self.assertEqual(cve.impact, {'availability': 'PARTIAL', 'confidentiality': 'PARTIAL', 'integrity': 'PARTIAL'})
        self.assertEqual(cve.references, ['https://cwiki.apache.org/confluence/display/STRUTS2/S2-045'])
        self.assertEqual(cve.vulnerable_products, ['Apache Struts 2 2.3.16', 'Apache Struts 2 2.5.x < 2.5.10.1'])
        self.assertEqual(cve.cvss_score, 9.3)
        self.assertEqual(cve.cvss_vector, 'CVSS:3.0/AV:N/AC:M/Au:N/C:P/I:P/A:P')


if __name__ == '__main__':
    unittest.main()

