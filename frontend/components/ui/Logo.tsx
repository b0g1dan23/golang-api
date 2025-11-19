import Link from "next/link";
import Image from "next/image";
import logo from '@/public/logo.svg';

const Logo = ({ className }: { className?: string }) => {
  return (
    <Link href="/" className={`table ${className}`}>
      <Image src={logo} alt="Bogdan Stevanovic - Logo" height={64} />
    </Link>
  );
};
export default Logo;
