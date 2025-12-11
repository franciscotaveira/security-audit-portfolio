import React from 'react';

export const Footer: React.FC = () => {
    const currentYear = new Date().getFullYear();

    return (
        <footer className="footer">
            <div className="container">
                <div className="footer-content">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span>🔐</span>
                        <span style={{ fontWeight: '600' }}>Solar Orion</span>
                        <span style={{ color: 'var(--color-text-muted)' }}>
                            © {currentYear} Francisco Taveira
                        </span>
                    </div>

                    <div className="footer-links">
                        <a
                            href="https://github.com/franciscotaveira"
                            className="footer-link"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            GitHub
                        </a>
                        <a
                            href="https://linkedin.com/in/franciscotaveira"
                            className="footer-link"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            LinkedIn
                        </a>
                        <a
                            href="mailto:contact@franciscotaveira.com"
                            className="footer-link"
                        >
                            Contact
                        </a>
                    </div>
                </div>

                <div style={{
                    marginTop: '1.5rem',
                    paddingTop: '1.5rem',
                    borderTop: '1px solid var(--color-border)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '1rem',
                    fontSize: '0.75rem',
                    color: 'var(--color-text-muted)'
                }}>
                    <div>
                        <strong>💼 Services:</strong> Security Audits • Penetration Testing • Consulting
                    </div>
                    <div>
                        <strong>📦 License:</strong> Proprietary - All Rights Reserved
                    </div>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
