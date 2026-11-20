import json
import unittest
from model_client import build_request, parse_response

class ModelContract(unittest.TestCase):
    def setUp(self):
        self.lock={'model':'deepseek-flash','thinking':{'type':'enabled'},'reasoning_effort':'high',
                   'max_tokens':32768,'top_p':1.0,'response_format':{'type':'json_object'}}
        self.messages=[{'role':'system','content':'Produce JSON.'},{'role':'user','content':'task'}]
    def test_request_has_locked_fields_and_no_tools(self):
        req=build_request(self.lock,self.messages)
        self.assertEqual(req['max_tokens'],32768)
        self.assertEqual(req['top_p'],1.0)
        self.assertEqual(req['reasoning_effort'],'high')
        self.assertNotIn('tools',req)
        self.assertNotIn('temperature',req)
    def test_complete_response_and_failed_content(self):
        response={'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'proposals':[{'parent':'before','factor':'guard_contract','intent':'check and continue','source':'int f(void){return 0;}'}]}),'reasoning_content':'reasoning'}}]}
        self.assertEqual(parse_response(response)['status'],'valid_output')
        response['choices'][0]['finish_reason']='length'
        self.assertEqual(parse_response(response)['reason'],'truncated')
        response['choices'][0]['finish_reason']='stop'
        response['choices'][0]['message']['content']='   '
        self.assertEqual(parse_response(response)['reason'],'blank_content')
        response['choices'][0]['message']['content']='not json'
        self.assertEqual(parse_response(response)['reason'],'invalid_json')

if __name__=='__main__': unittest.main()
