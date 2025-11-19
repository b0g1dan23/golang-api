export default function TermsOfService() {
    return (<>
        <h1>Terms of Service</h1>

        <div className="prose prose-gray max-w-none">
            <p className="text-gray-600 mb-8">Last updated: November 17, 2025</p>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">1. Acceptance of Terms</h2>
                <p className="text-gray-700 mb-4">
                    By accessing and using this service, you accept and agree to be bound by the terms and provision of this agreement.
                    If you do not agree to abide by the above, please do not use this service.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">2. Use License</h2>
                <p className="text-gray-700 mb-4">
                    Permission is granted to temporarily download one copy of the materials on our service for personal,
                    non-commercial transitory viewing only. This is the grant of a license, not a transfer of title, and under this license you may not:
                </p>
                <ul className="list-disc pl-6 mb-4 space-y-2">
                    <li>Modify or copy the materials</li>
                    <li>Use the materials for any commercial purpose or for any public display</li>
                    <li>Attempt to reverse engineer any software contained on our service</li>
                    <li>Remove any copyright or other proprietary notations from the materials</li>
                    <li>Transfer the materials to another person or "mirror" the materials on any other server</li>
                </ul>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">3. User Accounts</h2>
                <p className="text-gray-700 mb-4">
                    When you create an account with us, you must provide information that is accurate, complete, and current at all times.
                    Failure to do so constitutes a breach of the Terms, which may result in immediate termination of your account on our service.
                </p>
                <p className="text-gray-700 mb-4">
                    You are responsible for safeguarding the password that you use to access the service and for any activities or actions
                    under your password, whether your password is with our service or a third-party service.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">4. Prohibited Uses</h2>
                <p className="text-gray-700 mb-4">
                    You may use our service only for lawful purposes and in accordance with these Terms. You agree not to use the service:
                </p>
                <ul className="list-disc pl-6 mb-4 space-y-2">
                    <li>In any way that violates any applicable national or international law or regulation</li>
                    <li>To transmit, or procure the sending of, any advertising or promotional material without our prior written consent</li>
                    <li>To impersonate or attempt to impersonate the Company, a Company employee, another user, or any other person or entity</li>
                    <li>In any way that infringes upon the rights of others, or in any way is illegal, threatening, fraudulent, or harmful</li>
                    <li>To engage in any other conduct that restricts or inhibits anyone's use or enjoyment of the service</li>
                </ul>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">5. Intellectual Property</h2>
                <p className="text-gray-700 mb-4">
                    The service and its original content, features, and functionality are and will remain the exclusive property
                    of the Company and its licensors. The service is protected by copyright, trademark, and other laws of both
                    the country and foreign countries.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">6. Termination</h2>
                <p className="text-gray-700 mb-4">
                    We may terminate or suspend your account and bar access to the service immediately, without prior notice or liability,
                    under our sole discretion, for any reason whatsoever and without limitation, including but not limited to a breach of the Terms.
                </p>
                <p className="text-gray-700 mb-4">
                    If you wish to terminate your account, you may simply discontinue using the service or contact us to delete your account.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">7. Limitation of Liability</h2>
                <p className="text-gray-700 mb-4">
                    In no event shall the Company, nor its directors, employees, partners, agents, suppliers, or affiliates, be liable
                    for any indirect, incidental, special, consequential or punitive damages, including without limitation, loss of profits,
                    data, use, goodwill, or other intangible losses, resulting from your access to or use of or inability to access or use the service.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">8. Disclaimer</h2>
                <p className="text-gray-700 mb-4">
                    Your use of the service is at your sole risk. The service is provided on an "AS IS" and "AS AVAILABLE" basis.
                    The service is provided without warranties of any kind, whether express or implied, including, but not limited to,
                    implied warranties of merchantability, fitness for a particular purpose, non-infringement or course of performance.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">9. Governing Law</h2>
                <p className="text-gray-700 mb-4">
                    These Terms shall be governed and construed in accordance with the laws of your country, without regard to its
                    conflict of law provisions. Our failure to enforce any right or provision of these Terms will not be considered
                    a waiver of those rights.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">10. Changes to Terms</h2>
                <p className="text-gray-700 mb-4">
                    We reserve the right, at our sole discretion, to modify or replace these Terms at any time. If a revision is material,
                    we will provide at least 30 days notice prior to any new terms taking effect. What constitutes a material change will
                    be determined at our sole discretion.
                </p>
            </section>

            <section>
                <h2 className="text-2xl font-semibold text-gray-900 mb-4">11. Contact Us</h2>
                <p className="text-gray-700 mb-4">
                    If you have any questions about these Terms, please contact us at:
                </p>
                {process.env.NEXT_PUBLIC_EMAIL && (
                    <p className="text-gray-700">
                        Email: {process.env.NEXT_PUBLIC_EMAIL}<br />
                        {process.env.NEXT_PUBLIC_ADDRESS && (
                            <>
                                Address: {process.env.NEXT_PUBLIC_ADDRESS}
                            </>
                        )}
                    </p>
                )}
            </section>
        </div>
    </>
    );
}
