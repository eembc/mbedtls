# Compiling

```
% git clone git@github.com:hannestschofenig/mbedtls.git mbedtls-eembc
% cd !$
% git git checkout --track origin/eembc-setup
```

```
% mkdir build
% cd build
% cmake .. -DENABLE_TESTING=OFF
% make
```

# Running

Be sure to redirect the server output to /dev/null, otherwise it will corrupt the client redirect.

```
% cd ../eembc
% ./launch_server.bash >& /dev/null
% ./launch_client.bash > l1.txt
% fg
% <ctl-c> // kill server
% ./post-process-log.pl l1.txt > c1.txt
```

The post processor will now mute SHA calls if used inside ECDSA read/write.

The post processor now includes related calls to AES/ECB contexts for other functions (See the ^(0xAddr) reference in the output)

# Using the symbol decode & dynamic analyzer scripts

Turn on function instrumentation and compile with `ee_stubs.c` to create `trace.log`. Turn off prediction independent executable so that the addresses in `objdump` match the addresses we capture in the trace log.

```
% export CFLAGS='-finstrument-functions -g'
% export LDFLAGS='-no-pie'
```

After compiling you need to start the server in its own directory otherwise the trace.out files (the other is from the client) will overwrite each other!

Create a log filea as before by launching the client script.

```
% ./launch_client_tls_1_3.bash > log.txt    ; # this also creates trace.out
% objdump -D ssl/ssl_client2 > objects
% dynamic-calls-flat.pl objects trace.out          ; # this creates a HUGE flat call graph
% dynamic-calls-hier.pl objects trace.out          ; # this creates a HUGE hierarchical call graph
```

# Using `gprof`

To enable `gprof`, you need to first recompile with the GCC `-pg` options (this assumes you are using `gcc`):

```
% export CFLAGS=-pg
```

Then re-run `make` from the `build` folder.

Now that the `gprof` code has been installed into the binary, run the same steps above. The `ssl_client2` function will produce a file called `gmon.out` in the current working-directory. To create the `gprof` analysis report, run `gprof` with two arguments: the binary for the client, and the output file, like this:

```
gprof ./ssl/ssl_client2 gmon.out > analysis.txt
```

By default, `vim` should have syntax highlighting enabled for the analysis file, making it easier to read. The first table in the analysis file is the heatmap, followed by the static call charts. There is also a help file written into the analysis, which helps explain how to read the tables.


