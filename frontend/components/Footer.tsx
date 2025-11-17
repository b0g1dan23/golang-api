import Logo from "@/components/ui/Logo";
import Link from "next/link";

import { FaLinkedin, FaGithub, FaYoutube } from "react-icons/fa";

const Footer = () => {
  return (
    <footer className="py-24! border-t border-(--primary-800)">
      <div className="container">
        <div className="flex justify-between items-center max-md:flex-col max-md:text-center max-md:gap-[2.4rem]">
          <Logo />
          <ul className="flex gap-[4.8rem] max-md:flex-col max-md:gap-[1.6rem]">
            <li>
              <Link className="uppercase font-bold" href="/">
                Home
              </Link>
            </li>
            <li>
              <Link className="uppercase font-bold" href="/sign-up">
                Sign up
              </Link>
            </li>
            <li>
              <Link className="uppercase font-bold" href="/login">
                Login
              </Link>
            </li>
          </ul>
          <ul className="flex gap-[2.4rem]">
            {process.env.NEXT_PUBLIC_LINKEDIN_URL && (
              <li>
                <Link href={process.env.NEXT_PUBLIC_LINKEDIN_URL} target="_blank">
                  <FaLinkedin size={18} />
                </Link>
              </li>
            )}
            {process.env.NEXT_PUBLIC_GITHUB_URL && (
              <li>
                <Link href={process.env.NEXT_PUBLIC_GITHUB_URL} target="_blank">
                  <FaGithub size={18} />
                </Link>
              </li>
            )}
            {process.env.NEXT_PUBLIC_YOUTUBE_URL && (
              <li>
                <Link href={process.env.NEXT_PUBLIC_YOUTUBE_URL} target="_blank">
                  <FaYoutube size={18} />
                </Link>
              </li>
            )}
          </ul>
        </div>
        <hr className="text-(--primary-800) mt-24!" />
        <div className="flex items-center justify-center mt-[2.4rem]! gap-[2.4rem] max-md:flex-col">
          <p className="max-md:order-2">
            &copy; {new Date().getFullYear()} boge.dev | All rights reserved.
          </p>
          <ul className="flex gap-[1.2rem] max-md:order-1 max-md:flex-col max-md:text-center">
            <li>
              <Link className="underline" href="/privacy-policy">
                Privacy Policy
              </Link>
            </li>
            <li>
              <Link className="underline" href="/terms">
                Terms of Service
              </Link>
            </li>
            <li>
              <Link className="underline" href="/cookie-policy">
                Cookie Policy
              </Link>
            </li>
          </ul>
        </div>
      </div>
    </footer>
  );
};
export default Footer;
