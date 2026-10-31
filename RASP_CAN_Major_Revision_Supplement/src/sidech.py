import math,collections,sys,json
seq=collections.defaultdict(list)
for ln in open('seq_H100.csv'):
    s,i,a=ln.split(','); seq[(int(s),i)].append(int(a))
def H(cnt):
    n=sum(cnt.values()); return -sum(c/n*math.log2(c/n) for c in cnt.values() if c)
tot=0; h0=0; h1=0; per=[]
for k,v in seq.items():
    x=[a for a in v if a!=2]   # scheduled CHK is payload-independent (every H)
    if len(x)<100: continue
    c0=collections.Counter(x); c1=collections.defaultdict(collections.Counter)
    for a,b in zip(x,x[1:]): c1[a][b]+=1
    hc=sum(sum(c.values())*H(c) for c in c1.values())/max(1,len(x)-1)
    tot+=len(x); h0+=len(x)*H(c0); h1+=len(x)*hc; per.append((k,len(x),H(c0),hc,c0[1]/len(x)))
print("frames",tot,"H(R) bits/frame",h0/tot,"H(R|R-1)",h1/tot)
print("max per-ID H(R)",max(p[2] for p in per),"IDs",len(per),"IDs with H<0.01:",sum(p[2]<0.01 for p in per))
# window-quota shaping: per ID window of k records emits exactly Q escapes (dummy E64 chaff if fewer needed);
# Q set from the attack-free segments (seg 0,1) as the q-quantile of per-window escape counts; overflow windows leak 1 event.
def shaping(k,qtl):
    train=collections.defaultdict(list)
    for (s,i),v in seq.items():
        if s in (0,1):
            x=[a for a in v if a!=2]
            for w in range(0,len(x)-k+1,k): train[i].append(sum(1 for a in x[w:w+k] if a==1))
    Q={i:(sorted(c)[min(len(c)-1,int(qtl*len(c)))] if c else k) for i,c in train.items()}
    base=0; shaped=0; wins=0; over=0; frames=0
    for (s,i),v in seq.items():
        x=[a for a in v if a!=2]; q=Q.get(i,k)
        for w in range(0,len(x),k):
            blk=x[w:w+k]; e=sum(1 for a in blk if a==1); n=len(blk); qq=min(q,n)*n//k if n<k else q
            base+= (n-e)*1+e*2; emitted=max(e,qq); shaped+=(n-emitted)*1+emitted*2; wins+=1; over+= e>qq; frames+=n
    return Q, base, shaped, wins, over, frames
for k in (100,):
    for qtl in (0.95,0.99,1.0):
        Q,b,sh,w,o,fr=shaping(k,qtl)
        print(f"k={k} q={qtl}: protected-frame overhead vs adaptive {100*(sh-b)/b:.2f}%  overflow windows {100*o/w:.2f}%  (windows {w})")
# uniform two-frame (all E64) as zero-leak reference
b=sum(len([a for a in v if a!=2])+sum(1 for a in v if a==1) for v in seq.values()); u=sum(2*len([a for a in v if a!=2]) for v in seq.values())
print(f"uniform E64 overhead vs adaptive {100*(u-b)/b:.2f}%")
# hybrid: IDs whose attack-free escape share >= theta are pinned to E64 (constant shape, zero record-type leakage);
# remaining IDs stay adaptive. Leakage = frame-weighted H(R) over non-pinned IDs.
tr=collections.defaultdict(lambda:[0,0])
for (s,i),v in seq.items():
    if s in (0,1):
        for a in v:
            if a!=2: tr[i][0]+=1; tr[i][1]+= a==1
for th in (0.5,0.3,0.1,0.05):
    pin={i for i,(n,e) in tr.items() if n and e/n>=th}
    b=0;h=0;leak=0;fr=0
    for (s,i),v in seq.items():
        x=[a for a in v if a!=2]; n=len(x); e=sum(1 for a in x if a==1); b+=n+e; fr+=n
        if i in pin: h+=2*n
        else:
            h+=n+e; c=collections.Counter(x); leak+= n*H(c) if n else 0
    print(f"theta={th}: pinned IDs {len(pin)}  overhead {100*(h-b)/b:.2f}%  residual H(R) {leak/fr:.4f} bits/frame")
