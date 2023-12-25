import esprima
import escodegen

a = esprima.parse(open("/Users/xiayifan/Programs/js_static-main/demo/test/20151208_f989de6695f991a057247e7b57c25bcb.js").read())
with open("/Users/xiayifan/Programs/js_static-main/demo/test/1.js","w") as f:
    f.write(escodegen.generate(a,{"indent":"\t \t"}))