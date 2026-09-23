import io
from unittest.mock import patch
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
loader=importlib.machinery.SourceFileLoader('launcher',str(Path(__file__).with_name('proof-hunters')))
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec);loader.exec_module(m)
class LauncherTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'profiles').mkdir();(self.root/'bproof').write_bytes(b'test binary')
  old=m.ROOT;m.ROOT=self.root;self.addCleanup(setattr,m,'ROOT',old)
  self.profile={'network':'testnet','ready':True,'chainId':46630,'rpcUrl':'https://example.invalid','miningCore':'0x'+'1'*40,'basket':'0x'+'2'*40,'coreCodeSha256':hashlib.sha256(b'\x60\x00').hexdigest(),'basketCodeSha256':hashlib.sha256(b'\x60\x00').hexdigest(),'binarySha256':hashlib.sha256(b'test binary').hexdigest()}
  self.args=SimpleNamespace(network='testnet',command='mine',confirm_mainnet=False,keystore='wallet.json',max_fee_wei='100',max_attempts=50,passphrase_file=None,threads=None)
 def save(self): (self.root/'profiles'/f'{self.args.network}.json').write_text(json.dumps(self.profile))
 def rpc(self,url,method,params): return hex(46630) if method=='eth_chainId' else '0x6000'
 def test_single_bounded_submission(self):
  self.save();c=m.prepare(self.args,self.rpc);self.assertIn('--submit',c);self.assertNotIn('--loop',c);self.assertEqual(c[c.index('--max-fee')+1],'100');self.assertEqual(c[c.index('--max-attempts')+1],'50')
 def test_disabled_no_rpc(self):
  self.profile['ready']=False;self.save()
  with self.assertRaisesRegex(ValueError,'not cleared'):m.prepare(self.args,lambda *a:self.fail('RPC called'))
 def test_wrong_chain(self):
  self.save()
  with self.assertRaisesRegex(ValueError,'chain mismatch'):m.prepare(self.args,lambda *a:'0x1')
 def test_wrong_code(self):
  self.save()
  with self.assertRaisesRegex(ValueError,'bytecode mismatch'):m.prepare(self.args,lambda u,k,p:hex(46630) if k=='eth_chainId' else '0x')
 def test_binary_tamper(self):
  self.save();(self.root/'bproof').write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'checksum'):m.prepare(self.args,self.rpc)
 def test_no_fee(self):
  self.save();self.args.max_fee_wei=None
  with self.assertRaisesRegex(ValueError,'max-fee'):m.prepare(self.args,self.rpc)
 def test_mainnet_requires_ack(self):
  self.args.network='mainnet';self.profile['network']='mainnet';self.save()
  with self.assertRaisesRegex(ValueError,'confirm-mainnet'):m.prepare(self.args,self.rpc)
 def test_embedded_credentials_refused(self):
  self.profile['rpcUrl']='https://user:secret@example.invalid';self.save()
  with self.assertRaisesRegex(ValueError,'HTTPS'):m.prepare(self.args,self.rpc)
 def test_status_no_wallet(self):
  self.save();self.args.command='status';self.args.keystore=None
  self.assertNotIn('--keystore',m.prepare(self.args,self.rpc))
 def test_mainnet_rejects_testnet_chain_before_rpc(self):
  self.args.network='mainnet';self.args.confirm_mainnet=True;self.profile['network']='mainnet';self.save()
  with self.assertRaisesRegex(ValueError,'Mainnet profile must use chain 4663'):m.prepare(self.args,lambda *a:self.fail('RPC called'))
 def test_mainnet_status_uses_live_chain_without_wallet(self):
  self.args.network='mainnet';self.args.command='status';self.args.keystore=None;self.profile.update(network='mainnet',chainId=4663);self.save()
  command=m.prepare(self.args,lambda u,k,p:hex(4663) if k=='eth_chainId' else '0x6000')
  self.assertEqual(command[command.index('--chain-id')+1],'4663');self.assertNotIn('--keystore',command)
 def test_missing_binary_checksum_rejected(self):
  for missing in ['',None]:
   with self.subTest(checksum=missing):
    self.profile['binarySha256']=missing;self.save()
    with self.assertRaisesRegex(ValueError,'Missing release checksum'):m.prepare(self.args,lambda *a:self.fail('RPC called'))
 def test_rpc_identifies_cli_to_public_provider(self):
  def respond(request, timeout):
   self.assertEqual(request.get_header('User-agent'),'ProofHuntersCLI/0.2.0')
   self.assertEqual(json.loads(request.data)['method'],'eth_chainId')
   return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":"0x1237"}')
  with patch.object(m.urllib.request,'urlopen',side_effect=respond):
   self.assertEqual(m.rpc('https://example.invalid','eth_chainId',[]),'0x1237')
if __name__=='__main__':unittest.main()
