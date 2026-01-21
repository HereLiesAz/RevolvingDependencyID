# **The Revolving Dependency Identifier: A Comprehensive Framework for Build-Time Polymorphism and Moving Target Defense in Software Supply Chains**

## **1\. Introduction: The Imperative for Stochastic Software Engineering**

The contemporary software supply chain is predicated on stability, predictability, and immutability. These attributes, while fundamental to Reliability Engineering, have inadvertently calcified the attack surface of modern applications. In the current ecosystem, a library dependency—once published—retains a static identity. Its coordinates (Group ID, Artifact ID, Version), its internal package structure (e.g., com.example.auth), and its bytecode signature remain constant across millions of deployments. This static nature provides threat actors with an asymmetric advantage: they can analyze a dependency once, identify a vulnerability or a useful "gadget" for exploitation, and reliably execute attacks against any consumer of that library with zero modification to their payload.

This report investigates the architectural and technical realization of a **Revolving Dependency Identifier (RDI) Generator**. This proposed system disrupts the static analysis paradigm by introducing **Build-Time Polymorphism**. The core objective is to architect a generator that produces a mathematically unique, functionally identical, yet structurally distinct variant of a software dependency for every build request. By leveraging the ephemeral build capabilities of services like **JitPack**, coupled with advanced bytecode manipulation via the **Gradle Shadow Plugin** or **Maven Shade Plugin**, we can construct a pipeline where the namespace of a dependency is transient—generated on demand and never reused.

The following analysis explores the theoretical underpinnings of this approach in **Moving Target Defense (MTD)**, details the precise technical components required to construct the generator, and evaluates the profound implications such a system has on defeating class-loading exploits, gadget chains, and supply chain injection attacks.

### **1.1 The Vulnerability of Monoculture**

In biological systems, genetic diversity acts as a firewall against extinction events; a pathogen that kills one organism may not affect another due to genetic variation. In contrast, the software ecosystem is a monoculture. If log4j-core:2.14.1 contains a vulnerability, every application importing it contains the exact same vulnerability at the exact same location in the classpath.

Static analysis tools used by attackers rely on this predictability. Automated exploits scan for specific file paths, class names (Fully Qualified Names or FQNs), and method signatures. For instance, Java deserialization attacks—one of the most persistent threat vectors in enterprise Java—rely on "gadget chains." These are sequences of valid instructions found in common libraries (like Apache Commons Collections) that can be chained together to achieve Remote Code Execution (RCE) when an application deserializes an untrusted object.1 These chains function only because the attacker knows exactly where the gadget classes reside (e.g., org.apache.commons.collections.functors.InvokerTransformer). If the package name org.apache.commons.collections were to randomly mutate into com.x9f2.a7b1.collections during the build process, the attacker's pre-compiled exploit payload would fail, triggering a ClassNotFoundException rather than a shell.

### **1.2 Defining the Revolving Dependency Identifier**

The Revolving Dependency Identifier is a generated, high-entropy string that replaces the static root package of a library. The generator ensures that:

1. **On-Demand Generation:** The identifier is created at the moment of the build request.  
2. **Transient Existence:** The specific namespace configuration exists only for that specific build artifact.  
3. **Functional Equivalence:** Despite the structural changes, the compiled bytecode performs the exact same logic.  
4. **Discovery Transparency:** The consuming application can locate and utilize the library functions without hardcoding the randomized namespace.

The realization of this system requires a synergy between the **Build Agent** (JitPack), the **Transformation Engine** (Gradle/Maven plugins), and the **Discovery Protocol** (Java SPI).

## ---

**2\. Theoretical Framework: Moving Target Defense (MTD)**

The proposal for a Revolving Dependency Identifier is situated firmly within the cybersecurity domain of **Moving Target Defense (MTD)**. While traditional security focuses on hardening a static perimeter, MTD focuses on continuously shifting the system's configuration to increase uncertainty and complexity for the attacker.1

### **2.1 Entropy as a Defensive Metric**

The effectiveness of any MTD system is a function of its entropy. If the "revolving" nature of the identifier is predictable—for example, if it is based on a sequential counter or a simple timestamp—an attacker can predict the next state of the system.  
The proposed generator utilizes Cryptographic Entropy sourced from the build environment itself. By pulling randomness from the commit hash (SHA-1), build timestamp, or the underlying operating system's entropy pool (/dev/urandom), the generator creates a namespace that is computationally infeasible to predict.3

### **2.2 Software Diversification Techniques**

Research into software diversification identifies several layers where randomization can occur:

* **Instruction Set Randomization (ISR):** Changing the mapping of machine code instructions.4  
* **Address Space Layout Randomization (ASLR):** Randomizing the memory locations of program components.5  
* **Data Space Randomization (DSR):** Randomizing the storage location of variables to prevent buffer overflow exploits.5

The Revolving Dependency Identifier introduces **Namespace Layout Randomization (NLR)**. In the Java Virtual Machine (JVM), the "address" of a class is its Fully Qualified Name. By mutating the package structure, we are effectively performing ASLR at the bytecode level. The JVM loads classes based on their string names; changing com.auth.User to com.auth.x81.User changes the lookup key in the ClassLoader's internal map, effectively "moving" the code in the logical memory space of the application.6

### **2.3 The Economics of Attack and Defense**

MTD alters the economic asymmetry of cyber warfare. Currently, an attacker spends resources once to develop an exploit that works everywhere. With the Revolving Dependency Identifier, the attacker must spend resources to analyze *each specific instance* of the target application. If the dependency allows for a new namespace with *every build*, the attacker's knowledge becomes obsolete the moment a new deployment occurs. This drastically raises the cost of the attack, deterring opportunistic threat actors.7

## ---

**3\. Architecture of the Generator**

To create a revolving dependency identifier that is consumable by another application, we cannot simply randomize names in isolation. The system requires a coordinated architecture consisting of three primary components: **The Trigger**, **The Mutator**, and **The Bridge**.

### **3.1 Component 1: The Trigger (JitPack Build Agent)**

The "Trigger" is the mechanism that initiates the randomization process. Standard repositories like Maven Central host static, immutable artifacts. To achieve a revolving identifier, we need a repository that builds artifacts on demand.  
JitPack is uniquely suited for this role. It acts as a gateway between a source code repository (GitHub, GitLab, Bitbucket) and a package consumer.9

* **Mechanism:** When a build tool (Gradle/Maven) requests a dependency from JitPack (e.g., com.github.User:Repo:CommitHash), JitPack checks if that specific commit has been built. If not, it provisions a container, checks out the code, and runs the build.  
* **The Opportunity:** This "Just-In-Time" build process allows us to inject logic *before* the artifact is finalized. By manipulating the build environment during this ephemeral window, we can imprint a unique identity onto the resulting JAR.10

### **3.2 Component 2: The Mutator (Relocation Engine)**

The "Mutator" is the engine that performs the actual bytecode rewriting. It takes the source code or compiled classes and moves them from their original namespace (e.g., com.library.core) to a randomized namespace (e.g., com.library.gen\_a1b2c3.core).

* **Tools:** This is accomplished using the **Gradle Shadow Plugin** 12 or the **Maven Shade Plugin**.14  
* **Logic:** The Mutator must do more than just rename files. It must scan every class file to update:  
  * Package declarations.  
  * Import statements.  
  * String literals that reference class names (reflection hardening).  
  * Service Descriptor files (META-INF/services).16

### **3.3 Component 3: The Bridge (Discovery Protocol)**

The "Bridge" solves the consumption problem. If the package name is random, the consuming application cannot write static import statements (import com.random.MyClass). The Bridge allows the consumer to interact with the library through a stable interface while the implementation revolves.

* **Java SPI (Service Provider Interface):** The library exposes a stable interface in a fixed package (or a separate artifact). The implementation resides in the randomized package. The java.util.ServiceLoader mechanism is used to dynamically discover and load the implementation at runtime, regardless of its package name.18

## ---

**4\. Technical Deep Dive: The JitPack Build Environment**

The choice of JitPack is critical because it democratizes the build infrastructure. Unlike setting up a private Jenkins server to randomize builds, JitPack allows any open-source repository to become a polymorphic artifact generator simply by configuring a YAML file.

### **4.1 The Ephemeral Build Container**

When a request hits JitPack, it spins up a Docker container. This container is volatile; it exists solely to produce the artifacts for that specific commit. This isolation is the perfect environment for generating unique identifiers.

* **Environment Variables:** JitPack injects several environment variables into the build context: JITPACK=true, GIT\_COMMIT, GIT\_BRANCH, and VERSION.10  
* **Customization:** The jitpack.yml file allows the repository owner to execute arbitrary shell commands via the before\_install hook. This is where the entropy generation occurs.

### **4.2 Scripting the Randomizer in jitpack.yml**

To generate a completely new namespace on demand, we inject a script that runs before the build tool (Gradle/Maven) is invoked.

**Example jitpack.yml Configuration:**

YAML

jdk:  
  \- openjdk17  
before\_install:  
  \- \# Generate a random 8-character string using system entropy  
  \- export RANDOM\_ID=$(cat /dev/urandom | tr \-dc 'a-z0-9' | fold \-w 8 | head \-n 1)  
  \- echo "Generated Revolving ID: $RANDOM\_ID"  
  \- \# Modify the build.gradle file to inject this ID or pass it as a property  
  \-./scripts/inject\_id.sh $RANDOM\_ID  
install:  
  \- \# Pass the ID as a Gradle property  
  \-./gradlew shadowJar \-PrevolvingId=$RANDOM\_ID publishToMavenLocal

**Insight:** By using /dev/urandom, we ensure that even if the commit hash is the same, the generated ID *could* be different. However, JitPack caches the build result for a specific commit hash.20 This leads to a critical operational distinction: **Revolving per Commit** vs. **Revolving per Request**.

* **Revolving per Commit:** Since JitPack keys its cache by commit hash, the most reliable way to get a new namespace is to push a new commit. The generator ensures that *Artifact(Commit A)* has a different namespace than *Artifact(Commit B)*.  
* **Revolving per Request:** To force a rebuild of the *same* commit (and thus a new random ID), the consumer must use a SNAPSHOT version (e.g., master-SNAPSHOT) and configure their build tool to invalidate caches frequently (--refresh-dependencies or cache timeouts).11 Even then, JitPack's server-side cache might persist for a short duration. The "New Commit" strategy is the robust path for MTD.

### **4.3 Triggering Builds via Empty Commits**

To satisfy the requirement of "a new namespace with every build," the workflow must facilitate rapid, automated commits. A developer or CI system can push an Empty Commit to the repository to trigger a fresh JitPack build without modifying the actual source code.21  
Command: git commit \--allow-empty \-m "Trigger Revolving Build"  
This pushes a new SHA-1 hash to the repository. The consumer then updates their dependency version to this new hash. JitPack sees a "new" version, triggers the before\_install script, generates a new RANDOM\_ID, and produces an artifact with a completely novel namespace.

### **4.4 Environment Variable Injection for Build Tools**

The random ID generated in the shell must be passed to the build tool.

* **Gradle:** Use \-P flags (Project Properties). gradlew build \-PmyPackage=$RANDOM\_ID.22  
* Maven: Use \-D flags (System Properties). mvn install \-Dmy.package=$RANDOM\_ID.  
  This requires the build.gradle or pom.xml to be written dynamically to accept these variables, discussed in the next section.

## ---

**5\. The Engine: Bytecode Manipulation and Relocation**

The core "magic" of the generator lies in the transformation of the compiled bytecode. This is not source-code refactoring; it is post-compilation binary rewriting.

### **5.1 The Gradle Shadow Plugin**

The **Shadow Plugin** (specifically the com.gradleup.shadow variant) is the primary tool for this task.12 It is designed to bundle dependencies (Fat JAR) and relocate them to avoid classpath conflicts. We repurpose it to relocate the library *itself*.

#### **5.1.1 Configuring Dynamic Relocation**

The build.gradle file must be configured to read the injected property and apply the relocation pattern.

Groovy

plugins {  
    id 'com.gradleup.shadow' version '8.3.0'  
    id 'java'  
}

group \= 'com.github.MyUser'  
version \= '1.0.0'

// Read the revolving ID passed from JitPack, or default to 'static'  
def revolvingSuffix \= project.hasProperty('revolvingId')? project.revolvingId : 'static'  
def basePackage \= "com.library.core"  
def targetPackage \= "com.library.${revolvingSuffix}.core"

shadowJar {  
    // enable relocation  
    relocate basePackage, targetPackage  
      
    // Crucial for SPI: Merge service descriptors and rewrite them  
    mergeServiceFiles()   
      
    // Exclude metadata that breaks signatures  
    exclude 'META-INF/\*.SF'  
    exclude 'META-INF/\*.DSA'  
    exclude 'META-INF/\*.RSA'  
}

**Mechanism of Action:**

1. **Scanning:** The Shadow plugin uses ASM (a bytecode manipulation framework) to scan every class file in the project and its dependencies.  
2. **Rewriting:** It identifies every occurrence of the string com/library/core (internal binary name) and replaces it with com/library/a1b2c3/core. This includes:  
   * Class declarations (public class...).  
   * Field types and Method signatures.  
   * Import statements in the bytecode constant pool.  
   * String literals (if configured, though risky).  
3. **Output:** The result is a JAR file where the classes physically reside in the new directory structure, and all internal references are updated.13

### **5.2 The Maven Shade Plugin**

For Maven-based projects, the **Apache Maven Shade Plugin** performs an identical role.

**pom.xml Configuration:**

XML

\<plugin\>  
    \<groupId\>org.apache.maven.plugins\</groupId\>  
    \<artifactId\>maven-shade-plugin\</artifactId\>  
    \<version\>3.5.0\</version\>  
    \<configuration\>  
        \<relocations\>  
            \<relocation\>  
                \<pattern\>com.library.core\</pattern\>  
                \<shadedPattern\>com.library.${revolving.id}.core\</shadedPattern\>  
            \</relocation\>  
        \</relocations\>  
        \<transformers\>  
            \<transformer implementation\="org.apache.maven.plugins.shade.resource.ServicesResourceTransformer"/\>  
        \</transformers\>  
    \</configuration\>  
    \<executions\>  
        \<execution\>  
            \<phase\>package\</phase\>  
            \<goals\>\<goal\>shade\</goal\>\</goals\>  
        \</execution\>  
    \</executions\>  
\</plugin\>

The ${revolving.id} property is populated by the \-D flag passed in the jitpack.yml install command.

### **5.3 Handling SPI and META-INF/services**

One of the most complex aspects of relocation is handling Java's Service Provider Interface (SPI). SPI relies on files in META-INF/services/ named after an interface (e.g., com.library.api.MyService). The content of the file is the FQN of the implementation class (e.g., com.library.core.MyServiceImpl).

* **The Problem:** If we relocate com.library.core to com.library.random, the class name changes. However, if the text file in META-INF/services is not updated, the ServiceLoader will look for the old class name and fail.  
* **The Solution:** Both Shadow and Shade plugins provide a **ServicesResourceTransformer** (or ServiceFileTransformer in Gradle Shadow).  
  * This transformer parses the files in META-INF/services.  
  * It checks if the class names listed inside match any of the relocation patterns.  
  * It rewrites the content of the file to match the new, randomized package name.16  
  * Crucially, it also handles the *file name* itself if the interface being implemented is also part of the relocated package.

### **5.4 Risk: Reflection and String Literals**

A significant limitation of this generator is its impact on reflection.

* **Safe:** MyClass.class.getName() is safe because the class reference is updated in the bytecode constant pool.  
* **Unsafe:** Class.forName("com.library.core.MyClass") is unsafe. The string literal "com.library.core.MyClass" might not be updated by the relocation plugin unless string replacement is explicitly enabled.  
* **Mitigation:** The library code *must* avoid hardcoded string class names. It should rely on module-info.java, direct class references, or configuration files that are processed by the transformer.24

## ---

**6\. The Interface Bridge: Consuming the Unknowable**

The generator creates a dependency where the namespace is unknown until *after* the build. This presents a paradox for the consumer: How do you write code against a library that changes its name every day?

### **6.1 The Stable Interface / Unstable Implementation Pattern**

The robust solution is to separate the library into two artifacts:

1. **The API Artifact (Stable):** Contains Interfaces, Enums, and Exception definitions. This has a **fixed** namespace (e.g., com.library.api).  
2. **The Implementation Artifact (Volatile):** Contains the logic. This is the artifact processed by the Revolving Dependency Identifier generator. It depends on the API artifact.

**Workflow:**

* The Consumer declares a **compile-time** dependency on the **API Artifact**.  
* The Consumer declares a **runtime-only** dependency on the **Implementation Artifact** (the JitPack artifact).

### **6.2 Discovery via ServiceLoader**

The consumer code uses the standard Java ServiceLoader to access the functionality.

Java

package com.consumer.app;

// Import from the STABLE API  
import com.library.api.EncryptionProvider;  
import java.util.ServiceLoader;

public class SecurityModule {  
    public void encryptData(String data) {  
        // Look for ANY implementation on the classpath  
        ServiceLoader\<EncryptionProvider\> loader \= ServiceLoader.load(EncryptionProvider.class);  
          
        for (EncryptionProvider provider : loader) {  
            // We don't know the provider's class name or package, and we don't care.  
            provider.encrypt(data);  
            return;  
        }  
        throw new IllegalStateException("No encryption provider found\!");  
    }  
}

**Why this works:**

1. The EncryptionProvider interface is stable.  
2. The implementation artifact (built by JitPack) contains com.library.x9f2.Impl which implements EncryptionProvider.  
3. The META-INF/services/com.library.api.EncryptionProvider file in the implementation JAR has been rewritten by the ServiceFileTransformer to point to com.library.x9f2.Impl.19  
4. At runtime, the JVM classpath contains the randomized JAR. ServiceLoader reads the meta-file, loads the randomized class, and instantiates it. The consumer never references the randomized package directly.

### **6.3 Discovery via Reflection Scanning**

If the library structure does not support SPI (e.g., it's a utility library without interfaces), the consumer can use a classpath scanning library like **Reflections** to find classes based on annotations or supertypes.

Java

// Scan the entire classpath for classes annotated with @RevolvingEntry  
Reflections reflections \= new Reflections("");  
Set\<Class\<?\>\> types \= reflections.getTypesAnnotatedWith(RevolvingEntry.class);

for (Class\<?\> clazz : types) {  
    // Instantiate dynamically  
    Object instance \= clazz.getDeclaredConstructor().newInstance();  
    // Use via reflection or cast to a known common parent  
}

This approach is heavier at runtime but offers maximum flexibility, allowing the consumer to "fish" for the library components regardless of their package name.26

## ---

**7\. Implementation Roadmap: Constructing the Generator**

This section outlines the step-by-step construction of the generator, aggregating the research snippets into a cohesive guide.

### **Step 1: Repository Preparation**

Create a Git repository (e.g., RevolvingLib). Structure it with a clear separation between API (optional but recommended) and Implementation.

### **Step 2: The jitpack.yml Mutator**

Create jitpack.yml in the root. This is the control center.

YAML

\# jitpack.yml  
jdk:  
  \- openjdk17  
before\_install:  
  \# 1\. Generate the ID.   
  \# Using 'openssl rand' or '/dev/urandom' for high entropy.  
  \- export REV\_ID=$(head /dev/urandom | tr \-dc a-z | head \-c 10)  
    
  \# 2\. Log the ID for debugging (build logs are visible on JitPack)  
  \- echo "REVOLVING BUILD ID: $REV\_ID"  
    
  \# 3\. Modify gradle.properties to inject the variable  
  \- echo "revolvingId=$REV\_ID" \>\> gradle.properties  
    
install:  
  \# 4\. Trigger the Shadow Jar build.   
  \# JitPack usually runs 'install', we override to run shadowJar and publish.  
  \-./gradlew shadowJar publishToMavenLocal

* **Insight:** Appending to gradle.properties is often cleaner than passing command line args, as it persists the variable for the duration of the daemon's life.22

### **Step 3: The Gradle Build Configuration**

Configure build.gradle to use the Shadow plugin and the injected property.

Groovy

// build.gradle  
plugins {  
    id 'java-library'  
    id 'com.gradleup.shadow' version '8.3.0'  
    id 'maven-publish'  
}

group \= 'com.github.YourUsername'  
version \= '1.0' // JitPack overrides this with the tag/commit hash

repositories { mavenCentral() }

dependencies {  
    // Dependencies that should be shadowed (hidden inside the namespace)  
    implementation 'com.google.guava:guava:31.1-jre'  
    // The stable API (if separated)  
    implementation project(':api-module')  
}

// Logic to determine the target package  
def revId \= project.findProperty('revolvingId')?: 'localdev'  
def targetPkg \= "com.revolving.${revId}"

shadowJar {  
    archiveClassifier.set('') // Replace the main artifact  
      
    // Relocate the library's own code  
    relocate 'com.original.impl', targetPkg \+ '.impl'  
      
    // Relocate dependencies (Optional: prevents dependency hell)  
    relocate 'com.google.common', targetPkg \+ '.deps.google'  
      
    // Enable SPI transformation  
    mergeServiceFiles()  
}

// Publishing config is standard, JitPack handles the repo location  
publishing {  
    publications {  
        maven(MavenPublication) {  
            from components.java  
        }  
    }  
}

* **Insight on Relocation:** By relocating *dependencies* (like Guava) as well, the generator creates a truly self-contained, isolated artifact. This prevents "Dependency Hell" where the consumer app has a different version of Guava. The revolving library carries its own private, renamed Guava.28

### **Step 4: Forcing the Revolution**

To generate a new ID, the maintainer (or an automated bot) pushes an empty commit:

Bash

git commit \--allow-empty \-m "Revolve: $(date)"  
git push origin main

The consumer updates their build.gradle:

Groovy

implementation 'com.github.YourUsername:RevolvingLib:NewCommitHash'

JitPack sees the new hash, triggers the build, generates a new REV\_ID (e.g., mx7d2s), creates the JAR with com.revolving.mx7d2s.impl, and serves it.

## ---

**8\. Accomplishments and Strategic Implications**

What has this generator accomplished? It has transformed a static software asset into a **Moving Target**.

### **8.1 Disruption of Gadget Chains (Security)**

As previously established, gadget chains require precise knowledge of package paths. By relocating org.apache.commons... to com.revolving.mx7d2s.deps.commons..., any pre-compiled serialization exploit targeting the standard Commons Collections path will fail to find the class. This renders the library immune to broad, non-targeted attacks.1 The attacker must now download the *specific* build artifact used by the victim to craft a payload—a significantly higher bar than using a generic exploit.

### **8.2 Supply Chain Hardening**

If an attacker attempts to inject a malicious class into the library (e.g., via a compromised upstream dependency), the relocation process adds a layer of complexity. The malicious class typically expects to interface with other classes at known locations. If the entire neighborhood has moved, the injected malware may fail to execute or link, potentially crashing explicitly rather than running silently.

### **8.3 Automated Obfuscation**

While not a replacement for shrinking/obfuscation tools like R8, the RDI generator creates a binary that is hostile to reverse engineering. An analyst trying to map the software will find standard libraries (like logging or utility frameworks) at bizarre, non-standard paths. This increases the cognitive load required to understand the application's structure.

### **8.4 Dependency Conflict Resolution**

This generator acts as a "Silver Bullet" for dependency conflicts. If App X depends on Lib A (which uses Guava 19\) and Lib B (which uses Guava 30), a runtime crash usually ensues.  
If Lib A and Lib B both use the RDI generator, Lib A will contain com.rev.A.guava (v19) and Lib B will contain com.rev.B.guava (v30). Both versions coexist peacefully on the classpath, completely isolated from each other.28

## ---

**9\. Conclusion**

The **Revolving Dependency Identifier Generator** is a feasible and potent application of Moving Target Defense within the modern software build pipeline. By orchestrating **JitPack** as an ephemeral build agent and the **Shadow/Shade plugins** as bytecode mutation engines, developers can democratize the concept of software diversification.

While traditional security focuses on patching vulnerabilities *after* discovery, this system proactively neutralizes entire classes of exploits (deserialization, static targeting) by removing the attacker's ability to rely on the "known universe" of the application's structure. It requires a shift in consumption patterns—moving from static imports to Service Loading—but the trade-off yields a hardened, polymorphic artifact that is mathematically unique with every commit.

### **9.1 Summary of Parts Needed**

1. **Source Code Repository:** The host for the library logic.  
2. **JitPack Account:** The on-demand build service acting as the "Trigger".  
3. **jitpack.yml:** The script orchestrating entropy generation and variable injection.  
4. **Gradle Shadow Plugin (or Maven Shade):** The "Mutator" performing bytecode relocation and SPI rewriting.  
5. **Java ServiceLoader (SPI):** The "Bridge" allowing the consumer to use the library despite its shifting namespace.  
6. **Entropy Source:** /dev/urandom or CI variables (GIT\_COMMIT) to seed the unique identifier.

This architecture proves that security through diversity is not just a biological imperative but a viable software engineering strategy.

---

| Feature | Static Dependency | Revolving Dependency Identifier |
| :---- | :---- | :---- |
| **Namespace** | Fixed (e.g., com.lib) | Dynamic (e.g., com.lib.x9a2) |
| **Build Artifact** | Identical for all users | Unique per commit/build |
| **Exploit Surface** | Static, Predictable | Transient, Unpredictable |
| **Gadget Chain Risk** | High | Near Zero (due to path mismatch) |
| **Dependency Hell** | Frequent Conflicts | Isolated / Shadowed |
| **Consumption** | Static Import | SPI / Reflection / Bridge |
| **Caching** | Highly Efficient | Lower Efficiency (Requires Re-download) |

*Table 1: Comparison of Static vs. Revolving Dependencies across security and operational metrics.*

#### **Works cited**

1. A Survey on Moving Target Defense: Intelligently Affordable, Optimized and Self-Adaptive, accessed January 21, 2026, [https://www.mdpi.com/2076-3417/13/9/5367](https://www.mdpi.com/2076-3417/13/9/5367)  
2. Empirical Assessment of Network-based Moving Target Defense Approaches \- OSTI.GOV, accessed January 21, 2026, [https://www.osti.gov/servlets/purl/1408370](https://www.osti.gov/servlets/purl/1408370)  
3. atsuya046 / random-seed-kotlin Download \- JitPack, accessed January 21, 2026, [https://jitpack.io/p/atsuya046/random-seed-kotlin](https://jitpack.io/p/atsuya046/random-seed-kotlin)  
4. A Framework for Software Diversification with ISA Heterogeneity \- USENIX, accessed January 21, 2026, [https://www.usenix.org/system/files/raid20-wang-xiaoguang.pdf](https://www.usenix.org/system/files/raid20-wang-xiaoguang.pdf)  
5. A Tutorial on Moving Target Defense Approaches Within Automotive Cyber-Physical Systems \- Frontiers, accessed January 21, 2026, [https://www.frontiersin.org/journals/future-transportation/articles/10.3389/ffutr.2021.792573/full](https://www.frontiersin.org/journals/future-transportation/articles/10.3389/ffutr.2021.792573/full)  
6. Classloaders and Reflection. From The Well-Grounded Java Developer… | by Manning Publications | CodeX | Medium, accessed January 21, 2026, [https://medium.com/codex/classloaders-and-reflection-ba60a886528a](https://medium.com/codex/classloaders-and-reflection-ba60a886528a)  
7. Moving Target Techniques: Leveraging Uncertainty for Cyber Defense \- MIT Lincoln Laboratory, accessed January 21, 2026, [https://www.ll.mit.edu/media/6106](https://www.ll.mit.edu/media/6106)  
8. Moving Target Defense \- DLT Solutions, accessed January 21, 2026, [https://www.dlt.com/sites/default/files/resource-attachments/White%20Paper%20-%20Moving%20Target%20Defense.pdf](https://www.dlt.com/sites/default/files/resource-attachments/White%20Paper%20-%20Moving%20Target%20Defense.pdf)  
9. JitPack | Publish JVM and Android libraries, accessed January 21, 2026, [https://jitpack.io/](https://jitpack.io/)  
10. Building :: Documentation for JitPack.io, accessed January 21, 2026, [https://docs.jitpack.io/building/](https://docs.jitpack.io/building/)  
11. :: Documentation for JitPack.io, accessed January 21, 2026, [https://docs.jitpack.io/](https://docs.jitpack.io/)  
12. GradleUp/shadow: Gradle plugin to create fat/uber JARs, apply file transforms, and relocate packages for applications and libraries. Gradle version of Maven's Shade plugin. \- GitHub, accessed January 21, 2026, [https://github.com/GradleUp/shadow](https://github.com/GradleUp/shadow)  
13. Relocation \- Shadow Gradle Plugin \- GradleUp, accessed January 21, 2026, [https://gradleup.com/shadow/configuration/relocation/](https://gradleup.com/shadow/configuration/relocation/)  
14. Relocating Classes – Apache Maven Shade Plugin, accessed January 21, 2026, [https://maven.apache.org/plugins/maven-shade-plugin/examples/class-relocation.html](https://maven.apache.org/plugins/maven-shade-plugin/examples/class-relocation.html)  
15. Introduction – Apache Maven Shade Plugin, accessed January 21, 2026, [https://maven.apache.org/plugins/maven-shade-plugin/](https://maven.apache.org/plugins/maven-shade-plugin/)  
16. Merging \- Shadow Gradle Plugin, accessed January 21, 2026, [https://gradleup.com/shadow/configuration/merging/](https://gradleup.com/shadow/configuration/merging/)  
17. maven-shade-plugin/src/main/java/org/apache/maven/plugins/shade/resource/ServicesResourceTransformer.java at master \- GitHub, accessed January 21, 2026, [https://github.com/apache/maven-shade-plugin/blob/master/src/main/java/org/apache/maven/plugins/shade/resource/ServicesResourceTransformer.java](https://github.com/apache/maven-shade-plugin/blob/master/src/main/java/org/apache/maven/plugins/shade/resource/ServicesResourceTransformer.java)  
18. ServiceLoader (Java Platform SE 8 ) \- Oracle Help Center, accessed January 21, 2026, [https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html](https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html)  
19. The ServiceLoader and Native Dependency Injection in Java 11 | CINQ ICT, accessed January 21, 2026, [https://www.cinqict.nl/blog/serviceloader-and-native-dependency-injection-java-11](https://www.cinqict.nl/blog/serviceloader-and-native-dependency-injection-java-11)  
20. If the project was already built then JitPack will continue serving the existing artifacts. It will not rebuild the project at the new tag. In case you need to redo a release the best option is to create a new version on GitHub., accessed January 21, 2026, [https://docs.jitpack.io/faq/](https://docs.jitpack.io/faq/)  
21. How to Create and Push an Empty Commit in Git | Learn Version Control with Git, accessed January 21, 2026, [https://www.git-tower.com/learn/git/faq/git-empty-commit](https://www.git-tower.com/learn/git/faq/git-empty-commit)  
22. Build Environment Configuration \- Gradle User Manual, accessed January 21, 2026, [https://docs.gradle.org/current/userguide/build\_environment.html](https://docs.gradle.org/current/userguide/build_environment.html)  
23. Shadow Plugin Gradle: What does mergeServiceFiles() do? \- Stack Overflow, accessed January 21, 2026, [https://stackoverflow.com/questions/32887966/shadow-plugin-gradle-what-does-mergeservicefiles-do](https://stackoverflow.com/questions/32887966/shadow-plugin-gradle-what-does-mergeservicefiles-do)  
24. Maven Shade Plugin \- Excluding some a class of mine from being modified by the relocation process, accessed January 21, 2026, [https://stackoverflow.com/questions/45328585/maven-shade-plugin-excluding-some-a-class-of-mine-from-being-modified-by-the-r](https://stackoverflow.com/questions/45328585/maven-shade-plugin-excluding-some-a-class-of-mine-from-being-modified-by-the-r)  
25. How do I rename a Java .class file? \- Stack Overflow, accessed January 21, 2026, [https://stackoverflow.com/questions/15493425/how-do-i-rename-a-java-class-file](https://stackoverflow.com/questions/15493425/how-do-i-rename-a-java-class-file)  
26. How to instantiate a class without knowing its package? \- Stack Overflow, accessed January 21, 2026, [https://stackoverflow.com/questions/24237708/how-to-instantiate-a-class-without-knowing-its-package](https://stackoverflow.com/questions/24237708/how-to-instantiate-a-class-without-knowing-its-package)  
27. Can you find all classes in a package using reflection? \- Stack Overflow, accessed January 21, 2026, [https://stackoverflow.com/questions/520328/can-you-find-all-classes-in-a-package-using-reflection](https://stackoverflow.com/questions/520328/can-you-find-all-classes-in-a-package-using-reflection)  
28. \[JLBP-6\] Rename artifacts and packages together, accessed January 21, 2026, [http://jlbp.dev/JLBP-6](http://jlbp.dev/JLBP-6)  
29. Relocating Classes using Apache Maven Shade Plugin | by Ana Suzuki \- Medium, accessed January 21, 2026, [https://minyodev.medium.com/relocating-classes-using-apache-maven-shade-plugin-6957a1a8666d](https://minyodev.medium.com/relocating-classes-using-apache-maven-shade-plugin-6957a1a8666d)  
30. What is the maven-shade-plugin used for, and why would you want to relocate Java packages? \- Stack Overflow, accessed January 21, 2026, [https://stackoverflow.com/questions/13620281/what-is-the-maven-shade-plugin-used-for-and-why-would-you-want-to-relocate-java](https://stackoverflow.com/questions/13620281/what-is-the-maven-shade-plugin-used-for-and-why-would-you-want-to-relocate-java)
