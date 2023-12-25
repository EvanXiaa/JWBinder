import pickle
file = open("/Users/xiayifan/Programs/js_static-main/demo/timelog5","r")
file2 = open("/Users/xiayifan/Programs/js_static-main/demo/timelog3","w")
lines = file.readlines()
step = 0

current_backet = []
t_time_pdg = 0
t_time_wasm = 0
wtimes = []
ptimes = []
name2time = {}


pdg_time_span = {"1": 0, "3": 0, "7": 0, "5": 0, "10": 0, "20": 0, "40": 0, "60": 0, "80": 0}
wasm_time_span = {"1": 0, "3": 0, "7": 0, "5": 0, "10": 0, "20": 0,"40": 0, "60": 0, "80": 0}

for line in lines:
    if step == 5:
        step = 0
        if not line.startswith("0:0"):
            current_backet = [line]
            step += 1
            continue
        else:
            step = 0
            current_backet.append(line)
            time_pdg = 0
            time_wasm = 0
            for a in current_backet[1:-1]:
                if a.split()[-1][:-2] == 'e':
                    print(1)
                time_pdg += float(a.split()[-1][:-2])
            for a in current_backet:
                file2.write(a)
            t_time_pdg += time_pdg
            ptimes.append(time_pdg)
            timestap = current_backet[-1].split(":")
            time_wasm += int(timestap[1])*60 + float(timestap[2])
            t_time_wasm += time_wasm
            wtimes.append(time_wasm)
            name2time[current_backet[0][:-1]] = time_pdg+time_wasm

            if time_pdg < 1:
                pdg_time_span["1"] = pdg_time_span["1"] + 1
            elif time_pdg < 3:
                pdg_time_span["3"] = pdg_time_span["3"] + 1
            elif time_pdg < 5:
                pdg_time_span["5"] = pdg_time_span["5"] + 1
            elif time_pdg < 7:
                pdg_time_span["7"] = pdg_time_span["7"] + 1
            elif time_pdg < 10:
                pdg_time_span["10"] = pdg_time_span["10"]+ 1
            elif time_pdg < 20:
                pdg_time_span["20"] = pdg_time_span["20"] + 1
            elif time_pdg < 40:
                pdg_time_span["40"] = pdg_time_span["40"] + 1
            elif time_pdg < 60:
                pdg_time_span["60"] = pdg_time_span["60"] + 1

            if time_wasm < 1:
                wasm_time_span["1"] = wasm_time_span["1"]  +1
            elif time_wasm < 3:
                wasm_time_span["3"] = wasm_time_span["3"] + 1
            elif time_wasm < 5:
                wasm_time_span["5"] = wasm_time_span["5"] + 1
            elif time_wasm < 7:
                wasm_time_span["7"] = wasm_time_span["7"] + 1
            elif time_wasm < 10:
                wasm_time_span["10"] = wasm_time_span["10"] + 1
            elif time_wasm < 20:
                wasm_time_span["20"] = wasm_time_span["20"] + 1
            elif time_wasm < 40:
                wasm_time_span["40"] = wasm_time_span["40"] + 1
            elif time_wasm < 60:
                wasm_time_span["60"] = wasm_time_span["60"] + 1
            elif time_wasm < 80:
                wasm_time_span["80"] = wasm_time_span["80"] + 1
            current_backet = []
    elif step < 5:
        step += 1
        current_backet.append(line)
print(t_time_pdg/(99555/5))
print(t_time_wasm/(99555/5))
print(wasm_time_span)
print(pdg_time_span)

ptimes = sorted(ptimes)
wtimes = sorted(wtimes)

print(ptimes[len(ptimes)//2])
print(wtimes[len(wtimes)//2])
print(ptimes[-1])
print(wtimes[-1])
pickle.dump(name2time,open("/Users/xiayifan/Programs/js_static-main/demo/n2t","wb+"))