# ADR-0002: Ansible per raccolta e azioni, non system-upgrade-controller e kured

Stato: accettata (2026-10-21)

## Contesto

Per eseguire aggiornamenti e riavvii nel cluster esistono componenti pronti: system-upgrade-controller
(Job privilegiati sui nodi da risorse Plan) e kured (riavvii coordinati). In alternativa, Ansible.

## Decisione

Ansible per raccolta e remediation, eseguito dentro Kubernetes come Job. Un Job per nodo,
schedulato su un nodo diverso da quello bersaglio.

## Motivazioni

- Un solo drain per nodo: con system-upgrade-controller più kured il nodo viene drenato due volte
  (aggiornamento, poi riavvio).
- Lo stesso playbook funziona a cluster spento, dal bastion. I controller nel cluster no.
- Strumento già usato da kubespray: una competenza sola.
- Due componenti in meno da installare e mantenere; nessun DaemonSet privilegiato.

## Conseguenze

- Serve una chiave SSH dedicata in un Secret: va limitata (`from=` in `authorized_keys`, RBAC sul
  Secret, chiave usata solo da SAGE).
- Su cluster molto grandi o dove SSH è vietato, system-upgrade-controller e kured restano
  l'alternativa.
