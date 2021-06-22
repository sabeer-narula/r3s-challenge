# candidate-task-docker

This is a fun little task for R&D/engineering candidates to accomplish to help us in understanding how you approach solving technical problems!

## Task Requirements

Ciphertext: `f78D2XXh8tnSc8a5/FE=:0LDv4U8TeV918C/NvPLOpA==`

Encryption key: `risk3sixty`

1. Please see this repo that contains two Typescript files that were used to encrypt a plain text string. It provides all the details such as the encryption algorithm used, how an initialization vector is created, mocha tests you can use to confirm are working as needed, and a redacted `decrypt` function which is what you'll need to write yourself and use in your solution.

2. While the source code provided is in Typescript (and is built/executed in a Node.js environment), you **DO NOT** need to use this source code or a Javascript runtime/Node.js environment in your solution, use whatever language, runtime, etc. you'd like!

3. Your final deliverable is to create a repository with a `Dockerfile` we can use to build a container and execute to decrypt the ciphertext provided above.

## Testing your deliverable

When you provide us your final deliverable repository (this can be a tarball of source code, GitHub repo, GitLab, etc.), we will execute the following steps to confirm the solution is adequate:

1. If you provide a GitHub/GitLab repo, we will `git clone ...` this repo. If you provide a tarball we will untar it, `$ tar -xf yourRepo.tgz`

2. We will `cd` into the directory and build an image, `docker build -t r3sCandidate .`

3. We will run the image with `docker run ... r3sCandidate`. NOTE: it's totally fine if we need to provide extra parameters to the `docker run` command like environment variables or override the default command. Just let us know what should be added and we can ensure they're present in the command.

4. The execution of the container should print to the screen the decrypted plain text of the solution. Here's an example:

```sh
MAC-SR:docker-encryption lancewhatley$ docker run [?EXTRA_PARAMS] r3sCandidate [?OVERRIDDEN_COMMAND]


> candidate-task-docker-solution@0.0.1 start /usr/encryption
> node dist/decryptString.js

[DECRYPTED_PLAIN_TEXT_SHOULD_SHOW_HERE]
```
