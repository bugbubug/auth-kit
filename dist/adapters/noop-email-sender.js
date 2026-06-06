/**
 * Dev/test EmailSender adapters — zero egress.
 *
 * Framework/runtime-agnostic: no Workers/CF/Hono/Node imports, no network. The
 * real CF adapter (wrapping the `send_email` Workers binding) lives elsewhere; in
 * dev/test the core's Email OTP flow stays fully exercisable without any send.
 */
/**
 * Discards every email. Use in dev/test when the rendered OTP is irrelevant and
 * you only need the flow to report "sent" without any egress.
 */
export class NoopEmailSender {
    async send(_email) {
        // Intentionally no-op: zero egress.
    }
}
/**
 * Captures every email in a public array instead of sending it. Tests read the
 * plaintext `code` off `sent[n]` to drive the verify step without any egress.
 */
export class RecordingEmailSender {
    /** Every email handed to `send`, in order. */
    sent = [];
    async send(email) {
        this.sent.push(email);
    }
}
//# sourceMappingURL=noop-email-sender.js.map