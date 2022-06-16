import datetime
import os
import unittest
import time

from operation import gbls
from operation.nvd import NvdCpe, NvdCve


class TestNvd(unittest.TestCase):

    def setUp(self):
        self.nvd_cpe = NvdCpe()
        self.nvd_cve = NvdCve()

    def test_cpe(self):
        self.nvd_cpe.download_cpe()
        my_cpe = gbls.nvddir + gbls.cpe_filename

        now = time.time()
        # check if CPE file available
        self.assertTrue(os.path.isfile(my_cpe))
        if os.path.isfile(my_cpe):
            # check if the CPE file is downloaded in previous two hour
            cpe_timestamp = os.path.getmtime(my_cpe)
            cpe_age = (now - cpe_timestamp) / (60 * 60)
            self.assertTrue(cpe_age < 2)
        self.nvd_cpe.read()
        df_cpe = self.nvd_cpe.get()
        self.assertTrue(not df_cpe.empty)
        self.nvd_cpe.save()
        self.nvd_cpe.load()
        df_cpe = self.nvd_cpe.get()
        self.assertTrue(not df_cpe.empty)

    def test_cve(self):
        year = datetime.datetime.now().year
        now = time.time()
        my_cve_filename = (
                gbls.nvdcve
                + str(year)
                + '.json'
        )
        self.nvd_cve.download_cve()
        self.assertTrue(os.path.isfile(my_cve_filename))
        if os.path.isfile(my_cve_filename):
            # check if the CPE file is downloaded in previous two hour
            cve_timestamp = os.path.getmtime(my_cve_filename)
            cve_age = (now - cve_timestamp) / (60 * 60)
            self.assertTrue(cve_age < 2)

        self.nvd_cve.read()
        df_cve = self.nvd_cve.get()
        self.assertTrue(not df_cve.empty)
        self.nvd_cve.save()
        self.nvd_cve.load()
        df_cve = self.nvd_cve.get()
        self.assertTrue(not df_cve.empty)


if __name__ == '__main__':
    unittest.main()
