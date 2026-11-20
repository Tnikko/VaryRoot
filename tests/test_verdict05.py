import unittest
from varyroot.verdict import classify

class Coverage(unittest.TestCase):
    def test_decisions(self):
        def row(i,event):
            return dict(input_id=i,event=event,accesses=int(event=="used"),reference_value=0,value=0)
        for events,label in [(["used","blocked"],"negative"),(["blocked","blocked"],"pending"),
                (["no_access","no_access"],"pending"),(["used"],"pending"),(["violation"],"positive")]:
            self.assertEqual(classify([0,1],[row(i,e) for i,e in enumerate(events)],normal_inputs=[0])["label"],label)
        with self.assertRaises(ValueError):
            classify([0,1],[row(0,"used"),row(0,"used")],normal_inputs=[0])
        with self.assertRaises(ValueError):
            classify([0,1],[row(1,"unknown")],normal_inputs=[0])
