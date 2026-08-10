# Manuscript Revision Guide: From Position Paper to Prototype Research Article

## Recommended title adjustment

Current conceptual title:

> Separating Evidence, Inference, Communication, and Effect in Governed AI Systems: A Separation-of-Authority Reference Model

Research-article variant:

> Separating Evidence, Inference, Communication, and Effect in Governed AI Systems: A Reference Model and Minimal Enforcement Evaluation

## Add one implementation research question

> **RQ5.** Can the proposed authority classes and invariants be enforced in a single-process reference implementation, and what failures become reachable when individual controls are removed?

An optional performance question:

> **RQ6.** What runtime and receipt-storage overhead does the reference enforcement profile introduce relative to an otherwise equivalent collapsed ablation?

## Revise the contribution list

Add:

> **Constructive implementation and evaluation.** We implement the authority model in a modular monolith, exhaustively explore a finite abstract transition system, execute invariant-directed fault and mutation tests under strict and ablated profiles, and measure runtime and receipt overhead.

Do not replace the paper's claim limits with a general assertion of safety or superiority.

## Insert a new section after the reference architecture

Suggested heading:

> Prototype Implementation and Controlled Evaluation

Use `METHODS_AND_RESULTS.md` as the starting text. Keep the following subsections:

1. Research questions
2. Prototype and worked workflow
3. Experimental method
4. Results
5. Interpretation
6. Threats to validity
7. Reproduction

## Revise the abstract

Add one concrete implementation/results sentence after the transition-model contribution. Template:

> We implement the model in a single-process reference kernel and evaluate it through exhaustive exploration of a finite abstract transition system, nine invariant-directed fault and mutation tests with targeted ablations, and an end-to-end overhead benchmark. In the reported artifact, the strict profile completed all valid traces, admitted none of the cataloged prohibited transitions, and reached no bad state in the abstract model; disabling each control exposed its corresponding counterexample.

Insert the actual trial count and measured timing only after regenerating the final result artifact. Avoid claiming that the evaluation proves the architecture safe or generally superior.

## Revise non-claims

Replace any statement that the paper contains no empirical result with:

> The evaluation establishes constructive feasibility and guard behavior within the implemented transition and fault models. It does not establish regulatory compliance, production security, improved decision quality, general safety, or superiority across architectures.

## Distinguish the evidence types

The manuscript should explicitly separate:

- **conceptual result:** authority taxonomy, transition semantics, and invariants;
- **constructive result:** a modular-monolith implementation with signed typed artifacts and receipts;
- **model result:** exhaustive reachability within the finite abstract transition system;
- **controlled implementation result:** strict-versus-ablation fault tests;
- **performance result:** implementation-specific runtime and receipt-size measurements;
- **unresolved external-validity question:** transfer to real models, institutions, distributed systems, and adversaries.

## Submission framing

Describe the manuscript as a research article presenting and evaluating a reference model, not as a position paper with code attached. The prototype and evaluation must be integrated into the paper's research questions, method, results, and limitations. Code availability alone does not change the article's content type.
